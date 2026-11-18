// Package dnsjournal is the gateway's DNS query journal (settings.dns_log;
// docs/architecture.md「网关解析日志」): the reader of the gateway
// SmartDNS's audit file and the bounded, restart-surviving, structured
// record it keeps.
//
// Who does what. The resolver (the Compose container meridian-smartdns)
// writes its own audit file, a regular file in RawDir, which is the one
// writable directory mounted into it. A separate host process, "meridian
// dns-journal" (Unit, root without any capability, low CPU and I/O
// priority), follows that file (tail.go), parses each line (parser.go) and
// appends a Record to the segment files in JournalDir (this file). The
// resolver never waits for the reader: it only appends to a regular file,
// and whether it is slowed by its own audit writes is a property of the
// resolver binary, which is why the feature is gated on a verified version
// (gate.go).
//
// One budget. Defaults: DefaultMaxAge, DefaultMaxRecords, DefaultMaxBytes.
// The byte budget covers everything this feature can hold (SplitBudget):
// the raw audit file with its rotated copies (Budget.Raw, enforced by the
// reader whatever the resolver does), the hand-off queue in the reader's
// memory (Budget.Queue = Queue × MaxLine) and the segment files
// (Budget.Journal). Whichever of age, records and bytes is reached first
// wins; the oldest segment goes.
//
// Never in the way of the reader either. Add never blocks: a full queue
// drops the record and counts it (Stats.Dropped). A failed write drops and
// counts (Stats.WriteErrors) and a fresh segment is tried a second later.
//
// Clearing is honest. A clear (Journal.Clear, Tailer.Clear, PurgeData;
// together Daemon.Clear) reports what it could not remove instead of
// succeeding regardless: a segment whose unlink failed stays indexed (it
// still answers queries and the next clear tries it again), an audit file
// that could not be emptied is skipped from where it ended (never read
// again from its start), and both are remembered on disk (clearMarkFile,
// the position file) so a restarted reader still knows them. Errors leave
// this package as fixed words only (ClearError): never a path or a name.
//
// Access. Directories 0700, files 0600, owned by root; the only reader of
// the segment files is this process, which answers fixed queries on a
// status socket that answers uid 0 only (daemon.go). Nothing here is ever
// logged: not a name, not an address, not a line.
package dnsjournal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Fixed names (compile renders them, the host agent uses them; neither
// takes one from a caller).
const (
	// Unit is the reader's systemd unit.
	Unit = "meridian-dns-journal.service"
	// StateDirName is the unit's StateDirectory; StateDir its path.
	StateDirName = "meridian-dnslog"
	StateDir     = "/var/lib/" + StateDirName
	// RawDir holds the resolver's audit file and its rotated copies: the one
	// directory mounted read-write into the resolver container (same path).
	RawDir = StateDir + "/raw"
	// JournalDir holds the structured segments (never mounted anywhere).
	JournalDir = StateDir + "/journal"
	// AuditBase is the audit file's name, AuditFile its path.
	AuditBase = "audit.log"
	AuditFile = RawDir + "/" + AuditBase
	// RuntimeDirName is the unit's RuntimeDirectory; StatusSocket the socket
	// the host agent reads.
	RuntimeDirName = "meridian-dns-journal"
	StatusSocket   = "/run/" + RuntimeDirName + "/status.sock"
	// AuditSizeKB and AuditNum are the resolver's own rotation settings
	// (audit-size, audit-num): well inside Budget.Raw.
	AuditSizeKB = 2048
	AuditNum    = 1
	// ReadyMarker starts the reader's ready line; the unit refuses to start
	// with a binary that does not contain it.
	ReadyMarker = "meridian-dns-journal-ready"
)

// Defaults and limits.
const (
	DefaultMaxRecords = 50000
	DefaultMaxAge     = 24 * time.Hour
	// DefaultMaxBytes is the whole budget (SplitBudget).
	DefaultMaxBytes = 32 << 20
	// MaxLine bounds one record line.
	MaxLine = 1024
	// MaxSegments bounds the segment files.
	MaxSegments = 32
	// Queue is the hand-off queue between the reader and the writer.
	Queue = 2048
	// SyncInterval is the fsync period while there are unsynced writes.
	SyncInterval = 5 * time.Second
	// PageMax bounds one page of a query.
	PageMax = 200
	// SummaryDevices bounds the devices of a summary; SummaryGroups the
	// groups and SummaryNames the names listed per device; summaryNameTrack
	// the distinct names counted per device while scanning.
	SummaryDevices   = 128
	SummaryGroups    = 16
	SummaryNames     = 10
	summaryNameTrack = 512
	// SummaryMACs bounds the distinct MACs listed per device address.
	SummaryMACs = 4
	blockSlack  = 4096
	segPrefix   = "dns-"
	segSuffix   = ".jsonl"
	// positionFile is the reader's saved position (tail.go), kept next to
	// the segments.
	positionFile = "position.json"
	// clearMarkFile names the segments an unfinished clear left behind, so
	// they are still known as residue after a restart.
	clearMarkFile = "clear-pending.json"
)

// Budget is the one byte budget split over everything the feature holds.
type Budget struct {
	Total int64 `json:"total"`
	// Raw: the audit file, its rotated copies and anything else in RawDir.
	Raw int64 `json:"raw"`
	// Queue: the hand-off queue (memory, not disk).
	Queue int64 `json:"queue"`
	// Journal: the segment files and the position file.
	Journal int64 `json:"journal"`
}

// SplitBudget splits total: a quarter for the raw side, queue × MaxLine for
// the queue, the rest for the segments.
func SplitBudget(total int64, queue int) Budget {
	if total <= 0 {
		total = DefaultMaxBytes
	}
	if queue <= 0 {
		queue = Queue
	}
	b := Budget{Total: total, Raw: total / 4, Queue: int64(queue) * MaxLine}
	b.Journal = total - b.Raw - b.Queue
	return b
}

// Record is one answered query.
type Record struct {
	ID uint64 `json:"id"`
	// Time is when the resolver wrote the line. TimeApprox: the zone of the
	// line's timestamp could not be established, Time is when the reader
	// read the line.
	Time       time.Time `json:"time"`
	TimeApprox bool      `json:"time_approx,omitempty"`
	// Client is the device's address as the resolver saw it. MAC is the
	// kernel neighbour table's entry for it when the line was read ("":
	// unknown — no entry, no lookup, or the line was read too long after it
	// was written for the table to say anything about that moment).
	Client string `json:"client"`
	MAC    string `json:"mac,omitempty"`
	Name   string `json:"name"`
	QType  int    `json:"qtype"`
	// Result is the class (parser.go: ResultAnswered, ResultNoAnswer,
	// ResultNoAnswerSlow).
	Result string `json:"result"`
	// Group is the resolver's upstream group as logged ("" unknown).
	Group     string `json:"group,omitempty"`
	ElapsedMS int64  `json:"elapsed_ms"`
	// Answers counts the addresses in the answer (the addresses themselves
	// are not kept); AnswersOther the result tokens that are not addresses.
	Answers      int `json:"answers"`
	AnswersOther int `json:"answers_other,omitempty"`
}

// Config configures Open. Zero bounds take the defaults.
type Config struct {
	Dir        string
	MaxRecords int
	MaxAge     time.Duration
	// MaxBytes is the segments' share of the budget (Budget.Journal).
	MaxBytes int64
	// Now, Queue, SyncInterval and Fault: tests only (nil / 0: time.Now,
	// Queue, SyncInterval, no injected fault).
	Now          func() time.Time
	Queue        int
	SyncInterval time.Duration
	Fault        Fault
}

// Stats describes the journal.
type Stats struct {
	Records  int   `json:"records"`
	Bytes    int64 `json:"bytes"`
	Segments int   `json:"segments"`
	// Dropped: records not written because the queue was full; WriteErrors
	// because a write failed; Oversized because the line was too long.
	Dropped     uint64     `json:"dropped"`
	WriteErrors uint64     `json:"write_errors"`
	Oversized   uint64     `json:"oversized"`
	Oldest      *time.Time `json:"oldest,omitempty"`
	Newest      *time.Time `json:"newest,omitempty"`
	MaxRecords  int        `json:"max_records"`
	MaxAgeS     int64      `json:"max_age_s"`
	// MaxBytes is the segments' share; Budget the whole split when the
	// reader set one.
	MaxBytes  int64   `json:"max_bytes"`
	Budget    *Budget `json:"budget,omitempty"`
	TornBytes int64   `json:"torn_bytes,omitempty"`
	// ClearedAt: the last clear that removed everything.
	ClearedAt *time.Time `json:"cleared_at,omitempty"`
	// Residual: segments that should be gone but whose deletion failed (nil:
	// none). They are counted in Records, Bytes and Segments above.
	Residual *Residual `json:"residual,omitempty"`
}

// Residual is what a failed deletion left in the journal: segments a clear
// or a bound tried to unlink and could not. They stay indexed — they still
// answer queries and count against the byte budget — and are tried again:
// by the next clear, and once a minute when a bound (not only a clear)
// wants them gone.
type Residual struct {
	Segments int   `json:"segments"`
	Records  int   `json:"records"`
	Bytes    int64 `json:"bytes"`
	// ClearAt: when the unfinished clear was asked (nil: no clear is
	// pending, a bound left them).
	ClearAt *time.Time `json:"clear_at,omitempty"`
}

// Fault is the tests' way to make a clear's file-system calls fail: it is
// called before each of them (op "readdir", "lstat", "remove", "truncate")
// with the path, and a non-nil error is that call's failure — nothing is
// touched. nil (production): every call is the real one.
type Fault func(op, path string) error

func (f Fault) fail(op, path string) error {
	if f == nil {
		return nil
	}
	return f(op, path)
}

func (f Fault) readDir(dir string) ([]os.DirEntry, error) {
	if err := f.fail("readdir", dir); err != nil {
		return nil, err
	}
	return os.ReadDir(dir)
}

func (f Fault) lstat(p string) (os.FileInfo, error) {
	if err := f.fail("lstat", p); err != nil {
		return nil, err
	}
	return os.Lstat(p)
}

func (f Fault) remove(p string) error {
	if err := f.fail("remove", p); err != nil {
		return err
	}
	return os.Remove(p)
}

// truncate empties the regular file at p in place (truncateRegular).
func (f Fault) truncate(p string) error {
	if err := f.fail("truncate", p); err != nil {
		return err
	}
	return truncateRegular(p, 0, -1)
}

// The parts of a clear an error can belong to.
const (
	// PartJournal: the structured journal's directory and segment files.
	PartJournal = "journal"
	// PartRaw: the raw directory — the audit file and its rotated copies.
	PartRaw = "raw"
)

// ClearError is one kind of failure of a clear, in fixed words: which part,
// which call, why, and how many files it happened for. It never carries a
// path, a file name or the system's error text.
type ClearError struct {
	// Part: PartJournal or PartRaw.
	Part string `json:"part"`
	// Op: "readdir", "lstat", "remove", "truncate" or "write" (the clear
	// mark that lets a restart know the residue).
	Op string `json:"op"`
	// Cause: "permission", "read_only", "busy", "no_space", "io" or "other".
	Cause string `json:"cause"`
	// Count: how many times (files) it happened.
	Count int `json:"count"`
}

// errCause is the fixed word for a file-system error.
func errCause(err error) string {
	switch {
	case errors.Is(err, syscall.EROFS):
		return "read_only"
	case errors.Is(err, os.ErrPermission):
		return "permission"
	case errors.Is(err, syscall.EBUSY), errors.Is(err, syscall.ETXTBSY):
		return "busy"
	case errors.Is(err, syscall.ENOSPC), errors.Is(err, syscall.EDQUOT):
		return "no_space"
	case errors.Is(err, syscall.EIO):
		return "io"
	}
	return "other"
}

// clearErrs collects a clear's failures by kind.
type clearErrs []ClearError

func (c *clearErrs) add(part, op string, err error) {
	if err == nil {
		return
	}
	cause := errCause(err)
	for i := range *c {
		if e := &(*c)[i]; e.Part == part && e.Op == op && e.Cause == cause {
			e.Count++
			return
		}
	}
	*c = append(*c, ClearError{Part: part, Op: op, Cause: cause, Count: 1})
}

func (c clearErrs) list() []ClearError {
	if len(c) == 0 {
		return nil
	}
	return append([]ClearError(nil), c...)
}

type segment struct {
	path      string
	first     uint64
	size      int64
	count     int
	oldest    time.Time
	newest    time.Time
	firstTime time.Time
	// cleared: a clear asked for this segment and its deletion failed (only
	// meaningful in Journal.stuck).
	cleared bool
}

func (sg *segment) note(r *Record) {
	sg.count++
	if sg.count == 1 {
		sg.oldest, sg.newest, sg.firstTime = r.Time, r.Time, r.Time
		return
	}
	if r.Time.Before(sg.oldest) {
		sg.oldest = r.Time
	}
	if r.Time.After(sg.newest) {
		sg.newest = r.Time
	}
}

// Journal is the structured record of one gateway.
type Journal struct {
	cfg     Config
	segMax  int64
	segRecs int
	segSpan time.Duration
	budget  int64
	Budget  *Budget // set by the reader for Stats; nil in tests

	ch       chan Record
	flushReq chan chan struct{}
	clearReq chan chan ClearReport
	quit     chan struct{}
	done     chan struct{}

	mu   sync.Mutex
	segs []*segment
	// stuck: segments whose deletion failed, oldest first; all of them are
	// older than segs. clearAt: when the clear some of them are left from
	// was asked (zero: none of them is).
	stuck   []*segment
	clearAt time.Time
	f       *os.File
	nextID  uint64
	dirty   bool
	lastErr time.Time
	torn    int64
	cleared *time.Time

	dropped, writeErr, oversized atomic.Uint64
	closed                       atomic.Bool
	closeOnce                    sync.Once
	// testHookWrite runs in the writer before each batch (tests only).
	testHookWrite func()
}

// Open opens (or creates) the journal in cfg.Dir, recovers it (torn tail,
// bounds) and starts its writer.
func Open(cfg Config) (*Journal, error) {
	if cfg.Dir == "" || !filepath.IsAbs(cfg.Dir) {
		return nil, fmt.Errorf("journal directory %q is not absolute", cfg.Dir)
	}
	if cfg.MaxRecords <= 0 {
		cfg.MaxRecords = DefaultMaxRecords
	}
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = DefaultMaxAge
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = SplitBudget(0, cfg.Queue).Journal
	}
	if cfg.Queue <= 0 {
		cfg.Queue = Queue
	}
	if cfg.SyncInterval <= 0 {
		cfg.SyncInterval = SyncInterval
	}
	j := &Journal{cfg: cfg, segMax: cfg.MaxBytes / 16, segRecs: (cfg.MaxRecords + 7) / 8, segSpan: cfg.MaxAge / 24}
	// One block per segment file, the position file, its temporary copy and
	// the clear mark.
	j.budget = cfg.MaxBytes - blockSlack*(MaxSegments+3)
	if j.segMax < MaxLine || j.budget < 2*j.segMax {
		return nil, fmt.Errorf("journal byte cap %d too small", cfg.MaxBytes)
	}
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(cfg.Dir, 0o700); err != nil {
		return nil, err
	}
	if err := j.recover(); err != nil {
		return nil, err
	}
	j.ch = make(chan Record, cfg.Queue)
	j.flushReq = make(chan chan struct{})
	j.clearReq = make(chan chan ClearReport)
	j.quit = make(chan struct{})
	j.done = make(chan struct{})
	go j.run()
	return j, nil
}

func (j *Journal) now() time.Time {
	if j.cfg.Now != nil {
		return j.cfg.Now()
	}
	return time.Now()
}

// Add hands r to the writer without ever blocking: when the queue is full
// the record is dropped and counted.
func (j *Journal) Add(r Record) {
	if j == nil || j.closed.Load() {
		return
	}
	select {
	case j.ch <- r:
	default:
		j.dropped.Add(1)
	}
}

// Close writes what is queued, fsyncs and stops the writer.
func (j *Journal) Close() {
	if j == nil {
		return
	}
	j.closeOnce.Do(func() {
		j.closed.Store(true)
		close(j.quit)
		<-j.done
		j.mu.Lock()
		j.closeActive()
		j.mu.Unlock()
		syncDir(j.cfg.Dir)
	})
}

func segName(first uint64) string { return fmt.Sprintf("%s%020d%s", segPrefix, first, segSuffix) }

var segNameRe = regexp.MustCompile(`^dns-(\d{20})\.jsonl$`)

// recover scans the directory: removes temporary files, cuts a torn tail of
// the newest segment, rebuilds each segment's counts and enforces the
// bounds. One segment is in memory at a time.
func (j *Journal) recover() error {
	ents, err := os.ReadDir(j.cfg.Dir)
	if err != nil {
		return err
	}
	var names []string
	for _, e := range ents {
		n := e.Name()
		switch {
		case strings.HasSuffix(n, ".tmp"):
			_ = os.Remove(filepath.Join(j.cfg.Dir, n))
		case segNameRe.MatchString(n) && e.Type().IsRegular():
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for i, n := range names {
		p := filepath.Join(j.cfg.Dir, n)
		_ = os.Chmod(p, 0o600)
		first, _ := strconv.ParseUint(segNameRe.FindStringSubmatch(n)[1], 10, 64)
		sg, torn, maxID, err := scanSegment(p, i == len(names)-1)
		if err != nil {
			return err
		}
		sg.first = first
		j.torn += torn
		if maxID >= j.nextID {
			j.nextID = maxID + 1
		}
		if sg.count == 0 {
			_ = os.Remove(p)
			continue
		}
		j.segs = append(j.segs, sg)
	}
	if j.nextID == 0 {
		j.nextID = 1
	}
	j.recoverResidue()
	j.enforce(0, 0)
	return nil
}

// recoverResidue marks again, after a restart, the segments an unfinished
// clear left behind (clearMarkFile names them): they are residue, not
// records that were written since.
func (j *Journal) recoverResidue() {
	m := readClearMark(j.cfg.Dir)
	if m == nil {
		return
	}
	// Ids never go back below what the mark saw: a segment written later
	// cannot get the name of one the mark lists.
	if m.Next > j.nextID {
		j.nextID = m.Next
	}
	named := make(map[string]bool, len(m.Segments))
	for _, n := range m.Segments {
		named[n] = true
	}
	var live []*segment
	for _, sg := range j.segs {
		if named[filepath.Base(sg.path)] {
			sg.cleared = true
			j.stuck = append(j.stuck, sg)
		} else {
			live = append(live, sg)
		}
	}
	j.segs = live
	if len(j.stuck) > 0 {
		j.clearAt = m.At
	}
	j.saveClearMark()
}

// scanSegment reads a segment's counts; for the newest one (cut) a torn
// last line is cut off the file.
func scanSegment(p string, cut bool) (*segment, int64, uint64, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, 0, 0, err
	}
	sg := &segment{path: p}
	var maxID uint64
	good := 0
	for off := 0; off < len(b); {
		nl := bytes.IndexByte(b[off:], '\n')
		if nl < 0 {
			break
		}
		var r Record
		if json.Unmarshal(b[off:off+nl], &r) == nil && r.ID > 0 {
			sg.note(&r)
			if r.ID > maxID {
				maxID = r.ID
			}
		}
		off += nl + 1
		good = off
	}
	sg.size = int64(len(b))
	var torn int64
	if good < len(b) {
		torn = int64(len(b) - good)
		if cut {
			if err := os.Truncate(p, int64(good)); err != nil {
				return nil, 0, 0, err
			}
			sg.size = int64(good)
		}
	}
	return sg, torn, maxID, nil
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
}

func (j *Journal) run() {
	defer close(j.done)
	syncT := time.NewTicker(j.cfg.SyncInterval)
	defer syncT.Stop()
	prune := time.NewTicker(time.Minute)
	defer prune.Stop()
	batch := make([]Record, 0, 256)
	drainAll := func() {
		for {
			select {
			case r := <-j.ch:
				j.writeBatch([]Record{r})
				continue
			default:
			}
			return
		}
	}
	for {
		select {
		case r := <-j.ch:
			batch = append(batch[:0], r)
		drain:
			for len(batch) < cap(batch) {
				select {
				case r := <-j.ch:
					batch = append(batch, r)
				default:
					break drain
				}
			}
			j.writeBatch(batch)
		case done := <-j.flushReq:
			drainAll()
			close(done)
		case reply := <-j.clearReq:
			// What is still queued was read before the clear was asked: it
			// goes with it instead of being written after it.
			for n := cap(j.ch); n > 0; n-- {
				select {
				case <-j.ch:
					continue
				default:
				}
				break
			}
			reply <- j.clearNow()
		case <-syncT.C:
			j.mu.Lock()
			j.syncActive()
			j.mu.Unlock()
		case <-prune.C:
			j.mu.Lock()
			j.retryStuck(false)
			j.enforce(0, 0)
			j.mu.Unlock()
		case <-j.quit:
			drainAll()
			return
		}
	}
}

// bound cuts every field of r to its limit.
func bound(r Record) Record {
	r.Client = clip(r.Client, 64)
	r.MAC = clip(r.MAC, 32)
	r.Name = clip(r.Name, MaxName)
	r.Result = clip(r.Result, 32)
	r.Group = clip(r.Group, MaxGroup)
	if r.QType < 0 || r.QType > 65535 {
		r.QType = 0
	}
	r.ElapsedMS = max(0, min(r.ElapsedMS, int64(1)<<40))
	r.Answers = max(0, min(r.Answers, MaxAnswerTokens))
	r.AnswersOther = max(0, min(r.AnswersOther, MaxAnswerTokens))
	return r
}

// writeBatch encodes and appends a batch, rotating and pruning as needed.
func (j *Journal) writeBatch(batch []Record) {
	if j.testHookWrite != nil {
		j.testHookWrite()
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	var buf bytes.Buffer
	var pending []Record
	flush := func() {
		if buf.Len() == 0 {
			return
		}
		sg := j.segs[len(j.segs)-1]
		if _, err := j.f.Write(buf.Bytes()); err != nil {
			j.writeErr.Add(uint64(len(pending)))
			j.lastErr = j.now()
			// The segment may end in a partial line now: close it (the
			// partial line is skipped when read) and start a fresh one later.
			j.closeActive()
		} else {
			sg.size += int64(buf.Len())
			for i := range pending {
				sg.note(&pending[i])
			}
			j.dirty = true
		}
		buf.Reset()
		pending = pending[:0]
	}
	for _, r := range batch {
		r = bound(r)
		r.ID = j.nextID
		line, err := json.Marshal(r)
		if err != nil || len(line)+1 > MaxLine {
			j.oversized.Add(1)
			continue
		}
		need := int64(len(line) + 1)
		if j.f == nil || j.needRotate(int64(buf.Len())+need, pending, r.Time) {
			flush()
			if !j.rotate(r.ID) {
				j.writeErr.Add(1)
				continue
			}
		}
		j.enforce(int64(buf.Len())+need, len(pending)+1)
		if j.f == nil {
			j.writeErr.Add(1)
			continue
		}
		j.nextID++
		buf.Write(line)
		buf.WriteByte('\n')
		pending = append(pending, r)
	}
	flush()
}

// needRotate: the active segment would pass its byte, record or time span
// limit with extra more bytes and the pending records.
func (j *Journal) needRotate(extra int64, pending []Record, at time.Time) bool {
	sg := j.segs[len(j.segs)-1]
	first, have := sg.firstTime, sg.count > 0
	if !have && len(pending) > 0 {
		first, have = pending[0].Time, true
	}
	switch {
	case sg.size+extra > j.segMax:
		return true
	case sg.count+len(pending) >= j.segRecs:
		return true
	case have && at.Sub(first) >= j.segSpan:
		return true
	}
	return false
}

func (j *Journal) rotate(id uint64) bool {
	if j.f != nil {
		j.closeActive()
	}
	if !j.lastErr.IsZero() && j.now().Sub(j.lastErr) < time.Second {
		return false // do not hammer a failing disk
	}
	p := filepath.Join(j.cfg.Dir, segName(id))
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		j.lastErr = j.now()
		return false
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		j.lastErr = j.now()
		return false
	}
	j.f = f
	j.segs = append(j.segs, &segment{path: p, first: id, size: st.Size()})
	syncDir(j.cfg.Dir)
	return true
}

func (j *Journal) syncActive() {
	if j.f != nil && j.dirty {
		_ = j.f.Sync()
		j.dirty = false
	}
}

func (j *Journal) closeActive() {
	if j.f == nil {
		return
	}
	j.syncActive()
	_ = j.f.Close()
	j.f = nil
	if n := len(j.segs); n > 0 && j.segs[n-1].count == 0 {
		_ = os.Remove(j.segs[n-1].path)
		j.segs = j.segs[:n-1]
	}
}

// enforce deletes the oldest segments until the bounds hold with extra more
// bytes and extraRecs more records about to be written: the byte budget,
// MaxRecords, the segment count and age (a segment whose newest record is
// older than MaxAge). The active segment is never deleted by the byte or
// record bounds; it cannot exceed them alone. A segment whose deletion
// fails is not forgotten (discard): its bytes keep counting against the
// byte budget, so what is on disk stays inside it as far as deleting newer
// segments can keep it there.
func (j *Journal) enforce(extra int64, extraRecs int) {
	cutoff := j.now().Add(-j.cfg.MaxAge)
	for len(j.segs) > 0 {
		active := j.f != nil && len(j.segs) == 1
		var size int64
		recs := 0
		for _, s := range j.stuck {
			size += s.size
		}
		for _, s := range j.segs {
			size += s.size
			recs += s.count
		}
		old := j.segs[0]
		over := size+extra > j.budget || recs+extraRecs > j.cfg.MaxRecords || len(j.segs) > MaxSegments ||
			(old.count > 0 && old.newest.Before(cutoff)) || (old.count == 0 && !active)
		if !over {
			return
		}
		if active {
			if old.count > 0 && old.newest.Before(cutoff) {
				// The only segment is the active one and wholly too old.
				_ = j.f.Close()
				j.f = nil
				j.segs = j.segs[:0]
				j.discard(old, false)
			}
			return
		}
		j.segs = j.segs[1:]
		j.discard(old, false)
	}
}

// unlink deletes a segment's file (a file that is already gone is deleted).
func (j *Journal) unlink(sg *segment) error {
	if err := j.cfg.Fault.remove(sg.path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// discard deletes a segment that was already taken out of segs. When the
// deletion fails the segment is kept in stuck: still indexed, still
// queryable, tried again later. cleared: a clear asked for it.
func (j *Journal) discard(sg *segment, cleared bool) error {
	err := j.unlink(sg)
	if err == nil {
		return nil
	}
	if sg.count == 0 && sg.size == 0 {
		return nil // nothing in it: an empty file is not residue
	}
	sg.cleared = sg.cleared || cleared
	j.stuck = append(j.stuck, sg)
	// A new segment never takes the name of one that is still on disk.
	if sg.first >= j.nextID {
		j.nextID = sg.first + 1
	}
	return err
}

// retryStuck tries again to delete the segments whose deletion failed: all
// of them (a clear), or those a bound wants gone — left by a bound, or
// older than MaxAge by now — leaving the rest of a clear's residue to the
// next clear. It returns the records removed and the errors.
func (j *Journal) retryStuck(all bool) (int, clearErrs) {
	var errs clearErrs
	if len(j.stuck) == 0 {
		return 0, errs
	}
	cutoff := j.now().Add(-j.cfg.MaxAge)
	n := 0
	keep := j.stuck[:0]
	for _, sg := range j.stuck {
		if !all && sg.cleared && !(sg.count > 0 && sg.newest.Before(cutoff)) {
			keep = append(keep, sg)
			continue
		}
		if err := j.unlink(sg); err != nil {
			sg.cleared = sg.cleared || all
			keep = append(keep, sg)
			errs.add(PartJournal, "remove", err)
			continue
		}
		n += sg.count
	}
	changed := len(keep) != len(j.stuck)
	for i := len(keep); i < len(j.stuck); i++ {
		j.stuck[i] = nil
	}
	j.stuck = keep
	if changed {
		j.saveClearMark()
	}
	return n, errs
}

// residual describes stuck (nil: nothing is).
func (j *Journal) residual() *Residual {
	if len(j.stuck) == 0 {
		return nil
	}
	r := &Residual{Segments: len(j.stuck)}
	for _, sg := range j.stuck {
		r.Records += sg.count
		r.Bytes += sg.size
		if sg.cleared && !j.clearAt.IsZero() {
			t := j.clearAt
			r.ClearAt = &t
		}
	}
	return r
}

// clearMark is the content of clearMarkFile.
type clearMark struct {
	At time.Time `json:"at"`
	// Next: the next record id when the mark was written.
	Next uint64 `json:"next"`
	// Segments: the file names of the segments the clear could not delete.
	Segments []string `json:"segments"`
}

func readClearMark(dir string) *clearMark {
	f, err := os.Open(filepath.Join(dir, clearMarkFile))
	if err != nil {
		return nil
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 16<<10))
	var m clearMark
	if err != nil || json.Unmarshal(b, &m) != nil {
		return nil
	}
	names := m.Segments[:0]
	for _, n := range m.Segments {
		if segNameRe.MatchString(n) {
			names = append(names, n)
		}
	}
	m.Segments = names
	return &m
}

// writeClearMark replaces the mark (best effort: on a file system that
// refuses the write the residue is still there after a restart, as plain
// records that a clear removes).
func writeClearMark(dir string, m clearMark) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	p := filepath.Join(dir, clearMarkFile)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// saveClearMark makes the mark say what stuck holds of a clear: written
// while some of it is left, removed once none is.
func (j *Journal) saveClearMark() error {
	var names []string
	for _, sg := range j.stuck {
		if sg.cleared {
			names = append(names, filepath.Base(sg.path))
		}
	}
	if len(names) == 0 {
		j.clearAt = time.Time{}
		if err := j.cfg.Fault.remove(filepath.Join(j.cfg.Dir, clearMarkFile)); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if j.clearAt.IsZero() {
		j.clearAt = j.now()
	}
	if err := j.cfg.Fault.fail("write", clearMarkFile); err != nil {
		return err
	}
	return writeClearMark(j.cfg.Dir, clearMark{At: j.clearAt.UTC(), Next: j.nextID, Segments: names})
}

// Stats describes the journal now.
func (j *Journal) Stats() Stats {
	j.mu.Lock()
	defer j.mu.Unlock()
	st := Stats{Segments: len(j.stuck) + len(j.segs), Dropped: j.dropped.Load(), WriteErrors: j.writeErr.Load(), Oversized: j.oversized.Load(),
		MaxRecords: j.cfg.MaxRecords, MaxAgeS: int64(j.cfg.MaxAge / time.Second), MaxBytes: j.cfg.MaxBytes, Budget: j.Budget,
		TornBytes: j.torn, ClearedAt: j.cleared, Residual: j.residual()}
	for _, s := range j.all() {
		st.Records += s.count
		st.Bytes += s.size
		if s.count == 0 {
			continue
		}
		if st.Oldest == nil || s.oldest.Before(*st.Oldest) {
			t := s.oldest
			st.Oldest = &t
		}
		if st.Newest == nil || s.newest.After(*st.Newest) {
			t := s.newest
			st.Newest = &t
		}
	}
	if st.Records > j.cfg.MaxRecords {
		st.Records = j.cfg.MaxRecords
	}
	return st
}

// all is every indexed segment, oldest first: the stuck ones, then segs.
func (j *Journal) all() []*segment {
	if len(j.stuck) == 0 {
		return j.segs
	}
	return append(append(make([]*segment, 0, len(j.stuck)+len(j.segs)), j.stuck...), j.segs...)
}

// ClearReport is what a clear of the journal did.
type ClearReport struct {
	// Cleared: the records that were deleted.
	Cleared int
	// Residual: what could not be deleted and is still indexed (nil:
	// nothing — the clear is complete).
	Residual *Residual
	// Unknown: the directory or a file in it could not be looked at, so
	// more may be left than Residual counts.
	Unknown bool
	// Errors: why, as fixed words.
	Errors []ClearError
}

// Clear deletes every record. It runs in the writer, between two batches:
// what was queued before the call is discarded with it, so nothing that
// was read before the clear is written after it. Only the segments whose
// files were really deleted leave the index; the others are reported
// (ClearReport.Residual), still answer queries, are remembered across a
// restart (clearMarkFile) and are tried again by the next Clear.
func (j *Journal) Clear() ClearReport {
	if j.closed.Load() {
		<-j.done
		return j.clearNow()
	}
	reply := make(chan ClearReport, 1)
	select {
	case j.clearReq <- reply:
		return <-reply
	case <-j.done:
		return j.clearNow()
	}
}

func (j *Journal) clearNow() ClearReport {
	j.mu.Lock()
	defer j.mu.Unlock()
	var rep ClearReport
	if j.f != nil {
		_ = j.f.Close()
		j.f = nil
	}
	j.dirty = false
	now := j.now()
	n, errs := j.retryStuck(true)
	rep.Cleared = n
	segs := j.segs
	j.segs = nil
	for _, sg := range segs {
		if err := j.discard(sg, true); err != nil {
			errs.add(PartJournal, "remove", err)
			continue
		}
		rep.Cleared += sg.count
	}
	if len(j.stuck) == 0 {
		j.cleared = &now
	} else {
		j.clearAt = now
	}
	j.sweepUntracked(&errs, &rep)
	if err := j.saveClearMark(); err != nil {
		// Without the mark a restart would not know the residue as a
		// clear's: the clear is not complete.
		errs.add(PartJournal, "write", err)
	}
	syncDir(j.cfg.Dir)
	rep.Residual, rep.Errors = j.residual(), errs.list()
	return rep
}

// sweepUntracked looks at the directory once more after a clear: a
// segment file that no index knows of (it appeared behind the index's
// back) is deleted too, or kept as residue when that fails. A directory or
// a file that cannot be looked at is an error and makes the result Unknown.
func (j *Journal) sweepUntracked(errs *clearErrs, rep *ClearReport) {
	fs := j.cfg.Fault
	ents, err := fs.readDir(j.cfg.Dir)
	if err != nil {
		if !os.IsNotExist(err) {
			errs.add(PartJournal, "readdir", err)
			rep.Unknown = true
		}
		return
	}
	known := make(map[string]bool, len(j.stuck))
	for _, sg := range j.stuck {
		known[filepath.Base(sg.path)] = true
	}
	for _, e := range ents {
		n := e.Name()
		if known[n] || !segNameRe.MatchString(n) {
			continue
		}
		p := filepath.Join(j.cfg.Dir, n)
		fi, err := fs.lstat(p)
		if err != nil {
			if !os.IsNotExist(err) {
				errs.add(PartJournal, "lstat", err)
				rep.Unknown = true
			}
			continue
		}
		if !fi.Mode().IsRegular() {
			continue
		}
		first, _ := strconv.ParseUint(segNameRe.FindStringSubmatch(n)[1], 10, 64)
		sg := &segment{path: p, first: first, size: fi.Size()}
		if scanned, _, _, err := scanSegment(p, false); err == nil {
			scanned.path, scanned.first = p, first
			sg = scanned
		}
		if err := j.discard(sg, true); err != nil {
			errs.add(PartJournal, "remove", err)
		}
	}
}

// Flush returns once everything queued before the call is written.
func (j *Journal) Flush() {
	if j == nil || j.closed.Load() {
		return
	}
	done := make(chan struct{})
	select {
	case j.flushReq <- done:
		<-done
	case <-j.done:
	}
}

// --------------------------------------------------------------- query ---

var resultClasses = map[string]bool{ResultAnswered: true, ResultNoAnswer: true, ResultNoAnswerSlow: true, ResultNoAnswerAny: true}

// GroupRe is what a group filter may look like (a SmartDNS group name).
var GroupRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

var macRe = regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)

// NormMAC is the canonical form of a MAC ("" when it is not one).
func NormMAC(s string) string {
	s = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), "-", ":"))
	if !macRe.MatchString(s) {
		return ""
	}
	return s
}

// MaxText bounds Query.Text.
const MaxText = 64

// Query is a page request. Every field is optional.
type Query struct {
	// Device is a client address (exact); MAC a client MAC (exact; records
	// without a MAC do not match).
	Device string `json:"device,omitempty"`
	MAC    string `json:"mac,omitempty"`
	// Result is a class (ResultAnswered … ResultNoAnswerAny).
	Result string `json:"result,omitempty"`
	// Group is a resolver group name (exact).
	Group string `json:"group,omitempty"`
	// From and To select the records written in [From, To) (RFC 3339).
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
	// Text is a case-insensitive substring of the name.
	Text string `json:"text,omitempty"`
	// Before is the cursor: only records with a smaller id (0: newest).
	Before uint64 `json:"before,omitempty"`
	// Limit is the page size (0: 50; at most PageMax).
	Limit int `json:"limit,omitempty"`
}

// SummaryQuery bounds a summary's time range.
type SummaryQuery struct {
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

type parsedQuery struct {
	Query
	device   netip.Addr
	from, to time.Time
	text     string
}

// Validate checks q (the host agent and the reader both do).
func (q Query) Validate() error {
	_, err := q.parse()
	return err
}

func parseRange(from, to string) (time.Time, time.Time, error) {
	var f, t time.Time
	var err error
	if from != "" {
		if f, err = time.Parse(time.RFC3339, from); err != nil {
			return f, t, errors.New("from: not an RFC 3339 time")
		}
	}
	if to != "" {
		if t, err = time.Parse(time.RFC3339, to); err != nil {
			return f, t, errors.New("to: not an RFC 3339 time")
		}
	}
	return f, t, nil
}

func (q Query) parse() (parsedQuery, error) {
	p := parsedQuery{Query: q}
	if q.Device != "" {
		a, err := netip.ParseAddr(q.Device)
		if err != nil || a.Zone() != "" {
			return p, errors.New("device: not an address")
		}
		p.device = a.Unmap()
	}
	if q.MAC != "" && NormMAC(q.MAC) != q.MAC {
		return p, errors.New("mac: not a MAC (aa:bb:cc:dd:ee:ff)")
	}
	if q.Result != "" && !resultClasses[q.Result] {
		return p, errors.New("result: unknown class")
	}
	if q.Group != "" && !GroupRe.MatchString(q.Group) {
		return p, errors.New("group: not a group name")
	}
	var err error
	if p.from, p.to, err = parseRange(q.From, q.To); err != nil {
		return p, err
	}
	if len(q.Text) > MaxText || strings.ContainsFunc(q.Text, isCtl) {
		return p, fmt.Errorf("text: at most %d bytes, no control characters", MaxText)
	}
	p.text = strings.ToLower(strings.TrimSpace(q.Text))
	switch {
	case q.Limit < 0 || q.Limit > PageMax:
		return p, fmt.Errorf("limit: 0..%d", PageMax)
	case q.Limit == 0:
		p.Limit = 50
	}
	return p, nil
}

// Values encodes q as the status socket's query string.
func (q Query) Values() url.Values {
	v := url.Values{}
	set := func(k, s string) {
		if s != "" {
			v.Set(k, s)
		}
	}
	set("device", q.Device)
	set("mac", q.MAC)
	set("result", q.Result)
	set("group", q.Group)
	set("from", q.From)
	set("to", q.To)
	set("text", q.Text)
	if q.Before > 0 {
		v.Set("before", strconv.FormatUint(q.Before, 10))
	}
	if q.Limit > 0 {
		v.Set("limit", strconv.Itoa(q.Limit))
	}
	return v
}

// QueryFrom decodes a query string (unknown and repeated keys are refused).
func QueryFrom(v url.Values) (Query, error) {
	var q Query
	for k, vs := range v {
		if len(vs) != 1 {
			return q, fmt.Errorf("%s: one value", k)
		}
		s := vs[0]
		switch k {
		case "device":
			q.Device = s
		case "mac":
			q.MAC = s
		case "result":
			q.Result = s
		case "group":
			q.Group = s
		case "from":
			q.From = s
		case "to":
			q.To = s
		case "text":
			q.Text = s
		case "before":
			n, err := strconv.ParseUint(s, 10, 64)
			if err != nil {
				return q, errors.New("before: not a number")
			}
			q.Before = n
		case "limit":
			n, err := strconv.Atoi(s)
			if err != nil {
				return q, errors.New("limit: not a number")
			}
			q.Limit = n
		default:
			return q, fmt.Errorf("unknown parameter %q", k)
		}
	}
	return q, q.Validate()
}

// SummaryQueryFrom decodes a summary's query string (from, to only).
func SummaryQueryFrom(v url.Values) (SummaryQuery, error) {
	var q SummaryQuery
	for k, vs := range v {
		if len(vs) != 1 || (k != "from" && k != "to") {
			return q, errors.New("parameters: from, to")
		}
	}
	q.From, q.To = v.Get("from"), v.Get("to")
	return q, q.Validate()
}

// Page is a query's answer: records newest first.
type Page struct {
	Records []Record `json:"records"`
	// Matched counts every visible record the filters match; NextBefore is
	// the cursor of the next (older) page, 0 when there is none.
	Matched    int    `json:"matched"`
	NextBefore uint64 `json:"next_before,omitempty"`
	Stats      Stats  `json:"stats"`
}

type segSnap struct {
	path string
	size int64
}

func (j *Journal) snapshot() []segSnap {
	j.mu.Lock()
	defer j.mu.Unlock()
	all := j.all()
	out := make([]segSnap, len(all))
	for i, s := range all {
		out[i] = segSnap{s.path, s.size}
	}
	return out
}

// each calls fn for every visible record, newest first (at most
// MaxRecords, none older than MaxAge), until fn returns false. Closed
// segments are immutable and the active one is read up to the size it had.
func (j *Journal) each(fn func(r *Record) bool) {
	cutoff := j.now().Add(-j.cfg.MaxAge)
	seen := 0
	segs := j.snapshot()
	for i := len(segs) - 1; i >= 0; i-- {
		f, err := os.Open(segs[i].path)
		if err != nil {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(f, segs[i].size))
		f.Close()
		if err != nil {
			continue
		}
		lines := bytes.Split(b, []byte{'\n'})
		for k := len(lines) - 1; k >= 0; k-- {
			if len(lines[k]) == 0 {
				continue
			}
			var r Record
			if json.Unmarshal(lines[k], &r) != nil || r.ID == 0 {
				continue
			}
			if r.Time.Before(cutoff) {
				continue
			}
			if seen++; seen > j.cfg.MaxRecords {
				return
			}
			if !fn(&r) {
				return
			}
		}
	}
}

func (p parsedQuery) match(r *Record) bool {
	switch p.Result {
	case "":
	case ResultNoAnswerAny:
		if r.Result != ResultNoAnswer && r.Result != ResultNoAnswerSlow {
			return false
		}
	default:
		if r.Result != p.Result {
			return false
		}
	}
	if p.device.IsValid() {
		a, err := netip.ParseAddr(r.Client)
		if err != nil || a.Unmap() != p.device {
			return false
		}
	}
	if p.MAC != "" && r.MAC != p.MAC {
		return false
	}
	if p.Group != "" && r.Group != p.Group {
		return false
	}
	if !p.from.IsZero() && r.Time.Before(p.from) {
		return false
	}
	if !p.to.IsZero() && !r.Time.Before(p.to) {
		return false
	}
	if p.text != "" && !strings.Contains(r.Name, p.text) {
		return false
	}
	return true
}

// Query answers one page, newest first.
func (j *Journal) Query(q Query) (Page, error) {
	p, err := q.parse()
	if err != nil {
		return Page{}, err
	}
	page := Page{Records: []Record{}}
	j.each(func(r *Record) bool {
		if !p.match(r) {
			return true
		}
		page.Matched++
		if p.Before > 0 && r.ID >= p.Before {
			return true
		}
		switch {
		case len(page.Records) < p.Limit:
			page.Records = append(page.Records, *r)
		case page.NextBefore == 0:
			page.NextBefore = page.Records[len(page.Records)-1].ID
		}
		return true
	})
	page.Stats = j.Stats()
	return page, nil
}

// NameCount is one name and how often it was asked.
type NameCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// DeviceSummary is one client address in a summary.
type DeviceSummary struct {
	Device string `json:"device"`
	// MAC is the newest record's MAC; MACs every distinct MAC seen for the
	// address in the range (at most SummaryMACs; more than one means the
	// address was used by more than one device) and NoMAC the records
	// without one.
	MAC       string         `json:"mac,omitempty"`
	MACs      []string       `json:"macs,omitempty"`
	NoMAC     int            `json:"no_mac,omitempty"`
	FirstSeen time.Time      `json:"first_seen"`
	LastSeen  time.Time      `json:"last_seen"`
	Total     int            `json:"total"`
	ByResult  map[string]int `json:"by_result"`
	// ByGroup counts each resolver group (the most frequent SummaryGroups,
	// the rest in OtherGroups).
	ByGroup     map[string]int `json:"by_group"`
	OtherGroups int            `json:"other_groups,omitempty"`
	// TopNames are the most asked names (at most SummaryNames) among the
	// first summaryNameTrack distinct names of the device; NamesTruncated
	// says more distinct names existed than were counted.
	TopNames       []NameCount `json:"top_names"`
	DistinctNames  int         `json:"distinct_names"`
	NamesTruncated bool        `json:"names_truncated,omitempty"`

	names map[string]int
}

// Summary is the per-device summary.
type Summary struct {
	Devices []DeviceSummary `json:"devices"`
	// Truncated: more devices than SummaryDevices (the most recently seen
	// are listed).
	Truncated bool  `json:"truncated,omitempty"`
	Stats     Stats `json:"stats"`
}

// Validate checks a summary request.
func (q SummaryQuery) Validate() error {
	_, _, err := parseRange(q.From, q.To)
	return err
}

// Summary aggregates the visible records per client address.
func (j *Journal) Summary(q SummaryQuery) (Summary, error) {
	from, to, err := parseRange(q.From, q.To)
	if err != nil {
		return Summary{}, err
	}
	by := map[string]*DeviceSummary{}
	const maxTracked = 4096
	j.each(func(r *Record) bool {
		if (!from.IsZero() && r.Time.Before(from)) || (!to.IsZero() && !r.Time.Before(to)) {
			return true
		}
		d := by[r.Client]
		if d == nil {
			if len(by) >= maxTracked {
				return true
			}
			d = &DeviceSummary{Device: r.Client, FirstSeen: r.Time, LastSeen: r.Time, ByResult: map[string]int{}, ByGroup: map[string]int{}, names: map[string]int{}}
			by[r.Client] = d
		}
		d.Total++
		if r.Time.Before(d.FirstSeen) {
			d.FirstSeen = r.Time
		}
		if r.Time.After(d.LastSeen) {
			d.LastSeen = r.Time
		}
		switch {
		case r.MAC == "":
			d.NoMAC++
		default:
			if d.MAC == "" {
				d.MAC = r.MAC // newest first
			}
			known := false
			for _, m := range d.MACs {
				known = known || m == r.MAC
			}
			if !known && len(d.MACs) < SummaryMACs {
				d.MACs = append(d.MACs, r.MAC)
			}
		}
		d.ByResult[r.Result]++
		g := r.Group
		if g == "" {
			g = "unknown"
		}
		d.ByGroup[g]++
		if _, ok := d.names[r.Name]; ok || len(d.names) < summaryNameTrack {
			d.names[r.Name]++
		} else {
			d.NamesTruncated = true
		}
		return true
	})
	type kv struct {
		k string
		n int
	}
	top := func(m map[string]int) []kv {
		all := make([]kv, 0, len(m))
		for k, n := range m {
			all = append(all, kv{k, n})
		}
		sort.Slice(all, func(a, b int) bool { return all[a].n > all[b].n || all[a].n == all[b].n && all[a].k < all[b].k })
		return all
	}
	out := Summary{Devices: []DeviceSummary{}}
	for _, d := range by {
		if len(d.ByGroup) > SummaryGroups {
			all := top(d.ByGroup)
			d.ByGroup = map[string]int{}
			for i, x := range all {
				if i < SummaryGroups {
					d.ByGroup[x.k] = x.n
				} else {
					d.OtherGroups += x.n
				}
			}
		}
		d.DistinctNames = len(d.names)
		d.TopNames = []NameCount{}
		for i, x := range top(d.names) {
			if i >= SummaryNames {
				break
			}
			d.TopNames = append(d.TopNames, NameCount{Name: x.k, Count: x.n})
		}
		d.names = nil
		out.Devices = append(out.Devices, *d)
	}
	sort.Slice(out.Devices, func(a, b int) bool {
		da, db := out.Devices[a], out.Devices[b]
		return da.LastSeen.After(db.LastSeen) || da.LastSeen.Equal(db.LastSeen) && da.Device < db.Device
	})
	if len(out.Devices) > SummaryDevices {
		out.Devices, out.Truncated = out.Devices[:SummaryDevices], true
	}
	out.Stats = j.Stats()
	return out, nil
}
