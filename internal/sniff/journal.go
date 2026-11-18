package sniff

// The connection journal: a bounded, restart-surviving record of the
// connections the forwarder handled (docs/architecture.md「设备连接日志」).
//
// Where and who. The journal lives in the forwarder's systemd
// StateDirectory (/var/lib/meridian-sniff, StateDirectoryMode=0700, owned by
// the forwarder's fixed uid SniffUID; compile.RenderSniffUnit). The
// forwarder writes it as itself: segment files are created 0600 and the
// directory is forced to 0700 at open, so only root (with
// CAP_DAC_OVERRIDE, i.e. an administrator's shell) and the forwarder's own
// uid can open them, never another local user. The host agent (root
// without CAP_DAC_OVERRIDE) cannot open them either: the only reader is the
// forwarder itself, answering fixed queries on its root-only status socket
// (GET /v1/journal, GET /v1/journal/summary, POST /v1/journal/clear).
//
// Format. Append-only JSON lines (one JournalRecord per line) in segment
// files named conn-<first id, 20 digits>.jsonl, oldest first. Each field
// has a byte limit (journalLimits) and a whole line at most
// JournalMaxLine bytes; a longer line is not written (counted).
//
// Bounds, all three enforced at once (defaults: DefaultJournalMaxRecords,
// DefaultJournalMaxAge, DefaultJournalMaxBytes):
//
//   - records: a segment is closed after MaxRecords/8 records; once the
//     records on disk exceed MaxRecords the oldest segment is deleted.
//     Queries never show more than the newest MaxRecords.
//   - age: a segment is closed once it spans MaxAge/24; a closed segment
//     whose newest record is older than MaxAge is deleted (checked on every
//     write and every minute). Queries never show a record older than
//     MaxAge; on disk one lingers at most MaxAge + MaxAge/24.
//   - bytes: a segment is closed at MaxBytes/16 bytes; before every write
//     the oldest segments are deleted until the data fits MaxBytes minus one
//     segment minus a filesystem-block allowance per file
//     (journalBlockSlack × JournalMaxSegments). The one segment of room is
//     what the name purge's temporary copy may use. So the files' contents
//     never exceed MaxBytes, rounding to filesystem blocks included for
//     blocks up to journalBlockSlack; at most JournalMaxSegments segment
//     files plus one temporary file and the marker (under 100 bytes) exist.
//
// Never in the way. Server.finish hands a record to Add, which never
// blocks: a full queue (the writer is slow, the disk is stalled) drops the
// record and counts it (JournalStats.Dropped). Write errors (disk full,
// I/O) drop the record, count it and retry with a fresh segment later; a
// journal that cannot be opened at start leaves the forwarder running
// without one (logged). Nothing here can fail or delay a connection.
//
// Durability. Each batch is written with one write(2) per segment; the
// file is fsynced every JournalSyncInterval while dirty, on rotation and on
// Close. A power loss loses at most the last few seconds; a torn last line
// is cut off at the next open (JournalStats.TornBytes) and a line that does
// not parse is skipped when read, so a crash never makes the journal
// unreadable.
//
// Records. One line per connection, written when the connection ends
// (Server.finish; the record model is described there): the bounds count
// connections, a reader never merges lines, and no line claims a result
// that was not reached. Retention, ordering and segment spans use the time
// a record was finished (ConnRecord.EndTime), so a long connection that
// ended a minute ago is kept for MaxAge from now. Connections still open
// are not in the journal (the forwarder's active view shows them).
//
// Stops. A marker file (journalMarker) exists while a forwarder has the
// journal open; it is rewritten every minute with the number of
// connections being relayed (JournalConfig.Active) and removed by Close,
// after the forwarder has finished every open connection (result
// shutdown). Finding it at open means the previous forwarder stopped
// without Close (killed, crashed, power loss): its open connections have
// no record. JournalStats.UncleanStop says so, with that process's last
// minute and the connections it had open then, until the next Clear.
//
// Names. A record holds the sniffed name only when the forwarder runs with
// --record-names. Opening the journal without it removes every name
// already on disk (each segment holding one is rewritten without names and
// renamed over the original, PurgedNames): turning recording off at the
// next install leaves no name readable.

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
	"time"
	"unicode/utf8"
)

// Journal defaults and limits.
const (
	DefaultJournalMaxRecords = 50000
	DefaultJournalMaxAge     = 24 * time.Hour
	DefaultJournalMaxBytes   = 32 << 20
	// JournalMaxLine bounds one record line.
	JournalMaxLine = 4096
	// JournalMaxSegments bounds the segment files.
	JournalMaxSegments = 32
	// JournalSyncInterval is the fsync period while there are unsynced
	// writes.
	JournalSyncInterval = 5 * time.Second
	// JournalQueue is the hand-off queue between connections and the writer.
	JournalQueue = 4096
	// JournalPageMax bounds one page of a query.
	JournalPageMax = 200
	// JournalSummaryDevices bounds the devices of a summary,
	// JournalSummaryTargets the targets listed per device.
	JournalSummaryDevices = 128
	JournalSummaryTargets = 24
	// journalBlockSlack is the filesystem block rounding allowed per file.
	journalBlockSlack = 4096
	journalSegPrefix  = "conn-"
	journalSegSuffix  = ".jsonl"
	// journalMarker exists while a forwarder has the journal open.
	journalMarker = "running"
)

// JournalRecord is one journal line: the connection record with its
// sequence number.
type JournalRecord struct {
	ID uint64 `json:"id"`
	ConnRecord
}

// JournalConfig configures OpenJournal. Zero bounds take the defaults.
type JournalConfig struct {
	Dir         string
	MaxRecords  int
	MaxAge      time.Duration
	MaxBytes    int64
	RecordNames bool
	// Active returns the connections being relayed (nil: unknown); it is
	// written into the marker every minute.
	Active func() int
	// Now is the clock (nil: time.Now); Queue the hand-off queue length
	// (0: JournalQueue); SyncInterval the fsync period (0:
	// JournalSyncInterval). Tests only.
	Now          func() time.Time
	Queue        int
	SyncInterval time.Duration
}

// JournalStats describes the journal (Health.Journal and every query).
type JournalStats struct {
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
	MaxBytes    int64      `json:"max_bytes"`
	RecordNames bool       `json:"record_names"`
	// TornBytes were cut from a torn last line at open; PurgedNames is the
	// number of records whose name was removed at open (names off).
	TornBytes   int64      `json:"torn_bytes,omitempty"`
	PurgedNames int        `json:"purged_names,omitempty"`
	ClearedAt   *time.Time `json:"cleared_at,omitempty"`
	// UncleanStop: the previous forwarder stopped without closing the
	// journal (killed, crashed, power loss); the connections it had open
	// have no record. Cleared by Clear.
	UncleanStop *UncleanStop `json:"unclean_stop,omitempty"`
}

// UncleanStop describes a stop without Close found at open.
type UncleanStop struct {
	// LastAlive is the previous process's last marker write (at most a
	// minute before it stopped); Active the connections it was relaying
	// then (-1: unknown). DetectedAt is when this process opened the
	// journal.
	LastAlive  time.Time `json:"last_alive"`
	Active     int       `json:"active"`
	DetectedAt time.Time `json:"detected_at"`
}

type segment struct {
	path         string
	first        uint64
	size         int64
	count        int
	oldest       time.Time
	newest       time.Time
	hasNewest    bool
	openedAt     time.Time
	firstRecTime time.Time
}

// Journal is the connection journal of one forwarder.
type Journal struct {
	cfg     JournalConfig
	segMax  int64 // bytes per segment
	segRecs int   // records per segment
	segSpan time.Duration
	budget  int64 // bytes all segments may hold

	ch       chan ConnRecord
	flushReq chan chan struct{}
	quit     chan struct{}
	done     chan struct{}

	mu      sync.Mutex // segs, f, w, nextID, dirty, stats below
	segs    []*segment
	f       *os.File
	nextID  uint64
	dirty   bool
	lastErr time.Time
	torn    int64
	purged  int
	cleared *time.Time
	unclean *UncleanStop

	dropped, writeErr, oversized atomic.Uint64
	closed                       atomic.Bool
	closeOnce                    sync.Once
	// testHookWrite runs in the writer before each batch (tests only).
	testHookWrite func()
}

// OpenJournal opens (or creates) the journal in cfg.Dir, recovers it
// (torn tail, leftover temporary files, names when cfg.RecordNames is off,
// bounds) and starts its writer.
func OpenJournal(cfg JournalConfig) (*Journal, error) {
	if cfg.Dir == "" || !filepath.IsAbs(cfg.Dir) {
		return nil, fmt.Errorf("journal directory %q is not absolute", cfg.Dir)
	}
	if cfg.MaxRecords <= 0 {
		cfg.MaxRecords = DefaultJournalMaxRecords
	}
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = DefaultJournalMaxAge
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = DefaultJournalMaxBytes
	}
	if cfg.Queue <= 0 {
		cfg.Queue = JournalQueue
	}
	if cfg.SyncInterval <= 0 {
		cfg.SyncInterval = JournalSyncInterval
	}
	j := &Journal{cfg: cfg, segMax: cfg.MaxBytes / 16, segRecs: (cfg.MaxRecords + 7) / 8, segSpan: cfg.MaxAge / 24}
	// One block per segment file, the purge's temporary file and the marker.
	j.budget = cfg.MaxBytes - j.segMax - journalBlockSlack*(JournalMaxSegments+2)
	if j.segMax < JournalMaxLine || j.budget < 2*j.segMax {
		return nil, fmt.Errorf("journal byte cap %d too small", cfg.MaxBytes)
	}
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, err
	}
	// The directory is the forwarder's own (StateDirectory): root-only
	// apart from the forwarder, whatever it was created with.
	if err := os.Chmod(cfg.Dir, 0o700); err != nil {
		return nil, err
	}
	if err := j.recover(); err != nil {
		return nil, err
	}
	j.readMarker()
	j.writeMarker()
	j.ch = make(chan ConnRecord, cfg.Queue)
	j.flushReq = make(chan chan struct{})
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
func (j *Journal) Add(r ConnRecord) {
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
		// A clean stop: the forwarder finished its open connections before.
		_ = os.Remove(filepath.Join(j.cfg.Dir, journalMarker))
		syncDir(j.cfg.Dir)
	})
}

type markerBody struct {
	At     time.Time `json:"at"`
	Active int       `json:"active"`
}

// readMarker notes a marker left by a forwarder that did not Close.
func (j *Journal) readMarker() {
	p := filepath.Join(j.cfg.Dir, journalMarker)
	fi, err := os.Lstat(p)
	if err != nil {
		return
	}
	u := &UncleanStop{LastAlive: fi.ModTime(), Active: -1, DetectedAt: j.now()}
	if fi.Mode().IsRegular() && fi.Size() <= 256 {
		var m markerBody
		if b, err := os.ReadFile(p); err == nil && json.Unmarshal(b, &m) == nil && !m.At.IsZero() {
			u.LastAlive, u.Active = m.At, m.Active
		}
	} else {
		_ = os.RemoveAll(p)
	}
	j.unclean = u
}

// writeMarker (re)writes the marker: now and the open connections. A
// failure only weakens the next start's report.
func (j *Journal) writeMarker() {
	m := markerBody{At: j.now(), Active: -1}
	if j.cfg.Active != nil {
		m.Active = j.cfg.Active()
	}
	b, _ := json.Marshal(m)
	_ = os.WriteFile(filepath.Join(j.cfg.Dir, journalMarker), b, 0o600)
}

// ------------------------------------------------------------ recovery ---

func segName(first uint64) string {
	return fmt.Sprintf("%s%020d%s", journalSegPrefix, first, journalSegSuffix)
}

var segNameRe = regexp.MustCompile(`^conn-(\d{20})\.jsonl$`)

// recover scans the directory: removes temporary files, cuts a torn tail
// of the newest segment, rebuilds each segment's counts, enforces the
// bounds and then, when names are not recorded, rewrites the remaining
// segments that still hold one. One segment is in memory at a time.
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
	withNames := map[*segment]bool{}
	for i, n := range names {
		p := filepath.Join(j.cfg.Dir, n)
		_ = os.Chmod(p, 0o600)
		first, _ := strconv.ParseUint(segNameRe.FindStringSubmatch(n)[1], 10, 64)
		sg, sc, err := scanSegment(p, i == len(names)-1)
		if err != nil {
			return err
		}
		sg.first = first
		j.torn += sc.torn
		if sc.maxID >= j.nextID {
			j.nextID = sc.maxID + 1
		}
		if sg.count == 0 {
			_ = os.Remove(p)
			continue
		}
		if sc.names > 0 {
			withNames[sg] = true
		}
		j.segs = append(j.segs, sg)
	}
	if j.nextID == 0 {
		j.nextID = 1
	}
	j.enforce(0, 0)
	if !j.cfg.RecordNames {
		keep := j.segs[:0]
		for _, sg := range j.segs {
			if !withNames[sg] {
				keep = append(keep, sg)
				continue
			}
			n, err := j.rewriteWithoutNames(sg)
			if err != nil {
				// A segment whose names cannot be removed is removed whole:
				// names must not outlive the setting.
				if rerr := os.Remove(sg.path); rerr != nil {
					return fmt.Errorf("remove names from %s: %v; removing it: %w", filepath.Base(sg.path), err, rerr)
				}
				j.purged += sg.count
				continue
			}
			j.purged += n
			keep = append(keep, sg)
		}
		j.segs = keep
	}
	return nil
}

type scanResult struct {
	torn  int64
	maxID uint64
	names int
}

// scanSegment reads a segment's counts; for the newest one (cut) a torn
// last line is cut off the file.
func scanSegment(p string, cut bool) (*segment, scanResult, error) {
	var sc scanResult
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, sc, err
	}
	sg := &segment{path: p}
	good := 0
	for off := 0; off < len(b); {
		nl := bytes.IndexByte(b[off:], '\n')
		if nl < 0 {
			break // torn: no end of line
		}
		var r JournalRecord
		if json.Unmarshal(b[off:off+nl], &r) == nil && r.ID > 0 {
			sg.note(r)
			if r.ID > sc.maxID {
				sc.maxID = r.ID
			}
			if r.Name != "" {
				sc.names++
			}
		}
		off += nl + 1
		good = off
	}
	sg.size = int64(len(b))
	if good < len(b) {
		sc.torn = int64(len(b) - good)
		if cut {
			if err := os.Truncate(p, int64(good)); err != nil {
				return nil, sc, err
			}
			sg.size = int64(good)
		}
	}
	return sg, sc, nil
}

// note counts r in sg by the time it was finished (EndTime).
func (sg *segment) note(r JournalRecord) {
	at := r.EndTime()
	sg.count++
	if sg.count == 1 || at.Before(sg.oldest) {
		sg.oldest = at
	}
	if !sg.hasNewest || at.After(sg.newest) {
		sg.newest, sg.hasNewest = at, true
	}
	if sg.count == 1 {
		sg.firstRecTime = at
	}
}

// rewriteWithoutNames replaces sg's file by a copy without any name: a
// temporary file in the same directory (at most one segment's size, the
// room the byte budget keeps free), fsynced, renamed over the original,
// directory fsynced. It returns the names removed.
func (j *Journal) rewriteWithoutNames(sg *segment) (int, error) {
	b, err := os.ReadFile(sg.path)
	if err != nil {
		return 0, err
	}
	var buf bytes.Buffer
	n := 0
	for _, line := range bytes.Split(b, []byte{'\n'}) {
		var r JournalRecord
		if len(line) == 0 || json.Unmarshal(line, &r) != nil || r.ID == 0 {
			continue
		}
		if r.Name != "" {
			n++
			r.Name = ""
		}
		out, err := json.Marshal(r)
		if err != nil {
			continue
		}
		buf.Write(out)
		buf.WriteByte('\n')
	}
	tmp := sg.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, err
	}
	_, err = f.Write(buf.Bytes())
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, sg.path)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return 0, err
	}
	syncDir(j.cfg.Dir)
	sg.size = int64(buf.Len())
	return n, nil
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
}

// --------------------------------------------------------------- writer ---

func (j *Journal) run() {
	defer close(j.done)
	syncT := time.NewTicker(j.cfg.SyncInterval)
	defer syncT.Stop()
	prune := time.NewTicker(time.Minute)
	defer prune.Stop()
	batch := make([]ConnRecord, 0, 256)
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
			for {
				select {
				case r := <-j.ch:
					j.writeBatch([]ConnRecord{r})
					continue
				default:
				}
				break
			}
			close(done)
		case <-syncT.C:
			j.mu.Lock()
			j.syncActive()
			j.mu.Unlock()
		case <-prune.C:
			j.mu.Lock()
			j.enforce(0, 0)
			j.mu.Unlock()
			j.writeMarker()
		case <-j.quit:
			for {
				select {
				case r := <-j.ch:
					j.writeBatch([]ConnRecord{r})
					continue
				default:
				}
				return
			}
		}
	}
}

// writeBatch encodes and appends a batch, rotating and pruning as needed.
func (j *Journal) writeBatch(batch []ConnRecord) {
	if j.testHookWrite != nil {
		j.testHookWrite()
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	var buf bytes.Buffer
	var pending []JournalRecord
	flush := func() {
		if buf.Len() == 0 {
			return
		}
		sg := j.segs[len(j.segs)-1]
		if _, err := j.f.Write(buf.Bytes()); err != nil {
			j.writeErr.Add(uint64(len(pending)))
			j.lastErr = j.now()
			// The segment may now end in a partial line: close it (a later
			// open cuts nothing from a closed segment, the partial line is
			// skipped when read) and start a fresh one next time.
			j.closeActive()
		} else {
			sg.size += int64(buf.Len())
			for _, r := range pending {
				sg.note(r)
			}
			j.dirty = true
		}
		buf.Reset()
		pending = pending[:0]
	}
	for _, r := range batch {
		jr := JournalRecord{ID: j.nextID, ConnRecord: j.bound(r)}
		line, err := json.Marshal(jr)
		if err != nil || len(line)+1 > JournalMaxLine {
			j.oversized.Add(1)
			continue
		}
		need := int64(len(line) + 1)
		if j.f == nil || j.needRotate(int64(buf.Len())+need, len(pending), pending, jr.EndTime()) {
			flush()
			if !j.rotate(jr.ID) {
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
		pending = append(pending, jr)
	}
	flush()
}

// needRotate: the active segment would pass its byte, record or time
// span limit with extra more bytes and the pending records.
func (j *Journal) needRotate(extra int64, npend int, pending []JournalRecord, at time.Time) bool {
	sg := j.segs[len(j.segs)-1]
	first, have := sg.firstRecTime, sg.count > 0
	if !have && npend > 0 {
		first, have = pending[0].EndTime(), true
	}
	switch {
	case sg.size+extra > j.segMax:
		return true
	case sg.count+npend >= j.segRecs:
		return true
	case have && at.Sub(first) >= j.segSpan:
		return true
	}
	return false
}

// rotate closes the active segment and opens a new one starting at id.
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
	j.segs = append(j.segs, &segment{path: p, first: id, size: st.Size(), openedAt: j.now()})
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
	// An empty active segment is not kept.
	if n := len(j.segs); n > 0 && j.segs[n-1].count == 0 {
		_ = os.Remove(j.segs[n-1].path)
		j.segs = j.segs[:n-1]
	}
}

// enforce deletes the oldest segments until the bounds hold with extra
// more bytes and extraRecs more records about to be written: the byte
// budget, MaxRecords, the segment count, and age (a segment whose newest record is older than MaxAge). The
// active segment (the last, when a file is open) is never deleted by the
// byte or record bounds; it cannot exceed them alone.
func (j *Journal) enforce(extra int64, extraRecs int) {
	cutoff := j.now().Add(-j.cfg.MaxAge)
	for len(j.segs) > 0 {
		active := j.f != nil && len(j.segs) == 1
		var bytes int64
		recs := 0
		for _, s := range j.segs {
			bytes += s.size
			recs += s.count
		}
		old := j.segs[0]
		over := bytes+extra > j.budget || recs+extraRecs > j.cfg.MaxRecords || len(j.segs) > JournalMaxSegments ||
			(old.count > 0 && old.newest.Before(cutoff)) || (old.count == 0 && !active)
		if !over {
			return
		}
		if active {
			if old.count > 0 && old.newest.Before(cutoff) {
				// The only segment is the active one and wholly too old:
				// start afresh.
				j.closeActiveRemove()
			}
			return
		}
		_ = os.Remove(old.path)
		j.segs = j.segs[1:]
	}
}

func (j *Journal) closeActiveRemove() {
	if j.f != nil {
		_ = j.f.Close()
		j.f = nil
	}
	if n := len(j.segs); n > 0 {
		_ = os.Remove(j.segs[n-1].path)
		j.segs = j.segs[:n-1]
	}
}

// Field limits of a journal record (bytes).
var journalLimits = struct {
	addr, name, ident, short, errText int
}{addr: 64, name: 253, ident: 96, short: 32, errText: 128}

// bound returns r with every field cut to its limit and without the name
// when names are not recorded.
func (j *Journal) bound(r ConnRecord) ConnRecord {
	l := journalLimits
	r.Source = clipBytes(r.Source, l.addr)
	r.Dest = clipBytes(r.Dest, l.addr)
	r.Upstream = clipBytes(r.Upstream, l.addr)
	r.MAC = clipBytes(r.MAC, l.short)
	r.Proto = clipBytes(r.Proto, l.short)
	r.Why = clipBytes(r.Why, l.short)
	r.By = clipBytes(r.By, l.short)
	r.Result = clipBytes(r.Result, l.short)
	r.MarkStatus = clipBytes(r.MarkStatus, l.short)
	r.RawMark = clipBytes(r.RawMark, l.short)
	r.View = clipBytes(r.View, l.short)
	r.End = clipBytes(r.End, l.short)
	r.Reason = clipBytes(r.Reason, l.short)
	r.DurationMS, r.BytesUp, r.BytesDown = clampCount(r.DurationMS), clampCount(r.BytesUp), clampCount(r.BytesDown)
	r.RuleID = clipBytes(r.RuleID, l.ident)
	r.Target = clipBytes(r.Target, l.ident)
	r.Error = clipBytes(r.Error, l.errText)
	if j.cfg.RecordNames {
		r.Name = clipBytes(r.Name, l.name)
	} else {
		r.Name = ""
	}
	if r.NameRule != nil {
		nr := *r.NameRule
		nr.ID = clipBytes(nr.ID, l.ident)
		nr.Target = clipBytes(nr.Target, l.ident)
		nr.By = clipBytes(nr.By, l.short)
		nr.Error = clipBytes(nr.Error, l.short)
		r.NameRule = &nr
	}
	return r
}

// clipBytes cuts s to at most n bytes on a rune boundary and drops control
// characters.
func clipBytes(s string, n int) string {
	if len(s) <= n && !strings.ContainsFunc(s, isCtl) {
		return s
	}
	s = strings.Map(func(r rune) rune {
		if isCtl(r) {
			return -1
		}
		return r
	}, s)
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

func isCtl(r rune) bool { return r < 0x20 || r == 0x7f }

// maxCount bounds the counts of a record (2^53-1: exact in JSON readers).
const maxCount = 1<<53 - 1

func clampCount(n int64) int64 {
	switch {
	case n < 0:
		return 0
	case n > maxCount:
		return maxCount
	}
	return n
}

// --------------------------------------------------------------- stats ---

// Stats describes the journal now.
func (j *Journal) Stats() JournalStats {
	j.mu.Lock()
	defer j.mu.Unlock()
	st := JournalStats{Segments: len(j.segs), Dropped: j.dropped.Load(), WriteErrors: j.writeErr.Load(), Oversized: j.oversized.Load(),
		MaxRecords: j.cfg.MaxRecords, MaxAgeS: int64(j.cfg.MaxAge / time.Second), MaxBytes: j.cfg.MaxBytes, RecordNames: j.cfg.RecordNames,
		TornBytes: j.torn, PurgedNames: j.purged, ClearedAt: j.cleared, UncleanStop: j.unclean}
	for _, s := range j.segs {
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

// Clear deletes every record (the panel's fixed "clear" action) and
// returns how many there were.
func (j *Journal) Clear() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	n := 0
	if j.f != nil {
		_ = j.f.Close()
		j.f = nil
	}
	for _, s := range j.segs {
		n += s.count
		_ = os.Remove(s.path)
	}
	j.segs = nil
	j.dirty = false
	now := j.now()
	j.cleared = &now
	j.unclean = nil
	syncDir(j.cfg.Dir)
	return n
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

// Result classes of a journal record (JournalQuery.Result, the summary's
// per-class counts; RecordClass).
//
// Success: ClassOK (the upstream answered: at least one byte from it
// reached the client). Failures (IsFailureClass, the "failed" filter, the
// summary's Failed): resolve_failed, dial_failed, relay_failed,
// no_response, mark, other, shutdown. Neither: rejected (a reject rule did
// what it says), client_closed (the client left before a decision, or
// without sending anything and nothing came back) and ended_unknown (a
// record of an older forwarder that wrote "ok" when the upstream connected,
// before the relay's end was known).
const (
	ClassOK            = "ok"
	ClassRejected      = "rejected"
	ClassResolveFailed = "resolve_failed"
	ClassDialFailed    = "dial_failed"
	ClassRelayFailed   = "relay_failed"
	ClassNoResponse    = "no_response"
	ClassClientClosed  = "client_closed"
	ClassMark          = "mark"
	ClassShutdown      = "shutdown"
	ClassEndedUnknown  = "ended_unknown"
	ClassOther         = "other"
	// Filters only: every failure class; records whose name gave no
	// address and that were handled by address (Why WhyUnresolved).
	ClassFailed         = "failed"
	ClassNameUnresolved = "name_unresolved"
)

// ResultClass is the class of a result.
func ResultClass(result string) string {
	switch result {
	case ResultOK:
		return ClassOK
	case "rejected":
		return ClassRejected
	case "resolve_failed":
		return ClassResolveFailed
	case "dial_failed":
		return ClassDialFailed
	case ResultRelayFailed, "upstream_write_failed":
		return ClassRelayFailed
	case ResultNoResponse:
		return ClassNoResponse
	case ResultClientClosed:
		return ClassClientClosed
	case "unknown_mark", "mark_missing":
		return ClassMark
	case ResultShutdown:
		return ClassShutdown
	}
	return ClassOther
}

// RecordClass is the class of a record: ResultClass, except that an "ok"
// without an end (written by an older forwarder when the upstream
// connected) is ClassEndedUnknown, never a success.
func RecordClass(r *ConnRecord) string {
	if r.Result == ResultOK && r.End == "" {
		return ClassEndedUnknown
	}
	return ResultClass(r.Result)
}

// IsFailureClass: the class counts as a failure.
func IsFailureClass(c string) bool {
	switch c {
	case ClassResolveFailed, ClassDialFailed, ClassRelayFailed, ClassNoResponse, ClassMark, ClassShutdown, ClassOther:
		return true
	}
	return false
}

var journalClasses = map[string]bool{ClassOK: true, ClassRejected: true, ClassResolveFailed: true, ClassDialFailed: true, ClassRelayFailed: true,
	ClassNoResponse: true, ClassClientClosed: true, ClassMark: true, ClassShutdown: true, ClassEndedUnknown: true, ClassOther: true,
	ClassFailed: true, ClassNameUnresolved: true}

// JournalTargetRe is what a target filter may look like (the target file's
// names: direct, reject, exit:<id>, group:<id>).
var JournalTargetRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:._-]{0,95}$`)

// JournalQuery is a page request. Every field is optional.
type JournalQuery struct {
	// Device is a client address (exact).
	Device string `json:"device,omitempty"`
	// Target is a target name (exact).
	Target string `json:"target,omitempty"`
	// Result is a class (ClassOK … ClassNameUnresolved).
	Result string `json:"result,omitempty"`
	// From and To select the connections open at some time in [From, To)
	// (RFC 3339): finished at or after From and started before To.
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
	// Text is a case-insensitive substring of the name; refused when names
	// are not recorded.
	Text string `json:"text,omitempty"`
	// Before is the cursor: only records with a smaller id (0: newest).
	Before uint64 `json:"before,omitempty"`
	// Limit is the page size (0: 50; at most JournalPageMax).
	Limit int `json:"limit,omitempty"`
}

// JournalSummaryQuery bounds a summary's time range.
type JournalSummaryQuery struct {
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

type parsedQuery struct {
	JournalQuery
	device   netip.Addr
	from, to time.Time
	text     string
}

// MaxJournalText bounds JournalQuery.Text.
const MaxJournalText = 64

// Validate checks q (the host agent and the forwarder both do).
func (q JournalQuery) Validate() error {
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

func (q JournalQuery) parse() (parsedQuery, error) {
	p := parsedQuery{JournalQuery: q}
	if q.Device != "" {
		a, err := netip.ParseAddr(q.Device)
		if err != nil {
			return p, errors.New("device: not an address")
		}
		p.device = a.Unmap()
	}
	if q.Target != "" && !JournalTargetRe.MatchString(q.Target) {
		return p, errors.New("target: not a target name")
	}
	if q.Result != "" && !journalClasses[q.Result] {
		return p, errors.New("result: unknown class")
	}
	var err error
	if p.from, p.to, err = parseRange(q.From, q.To); err != nil {
		return p, err
	}
	if len(q.Text) > MaxJournalText || strings.ContainsFunc(q.Text, isCtl) {
		return p, fmt.Errorf("text: at most %d bytes, no control characters", MaxJournalText)
	}
	p.text = strings.ToLower(strings.TrimSpace(q.Text))
	switch {
	case q.Limit < 0 || q.Limit > JournalPageMax:
		return p, fmt.Errorf("limit: 0..%d", JournalPageMax)
	case q.Limit == 0:
		p.Limit = 50
	}
	return p, nil
}

// Values encodes q as the status socket's query string.
func (q JournalQuery) Values() url.Values {
	v := url.Values{}
	set := func(k, s string) {
		if s != "" {
			v.Set(k, s)
		}
	}
	set("device", q.Device)
	set("target", q.Target)
	set("result", q.Result)
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

// JournalQueryFrom decodes the status socket's query string (unknown keys
// and repeated keys are refused).
func JournalQueryFrom(v url.Values) (JournalQuery, error) {
	var q JournalQuery
	for k, vs := range v {
		if len(vs) != 1 {
			return q, fmt.Errorf("%s: one value", k)
		}
		s := vs[0]
		switch k {
		case "device":
			q.Device = s
		case "target":
			q.Target = s
		case "result":
			q.Result = s
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

// JournalPage is a query's answer.
type JournalPage struct {
	RecordNames bool            `json:"record_names"`
	Records     []JournalRecord `json:"records"`
	// Matched counts every visible record the filters match; NextBefore is
	// the cursor of the next (older) page, 0 when there is none. Records
	// are in the order they were finished, newest first.
	Matched    int          `json:"matched"`
	NextBefore uint64       `json:"next_before,omitempty"`
	Stats      JournalStats `json:"stats"`
	// Active: on the first page (no cursor) of a query without a result
	// filter, the forwarder's connections still being relayed that match
	// the device, target, time and text filters (Result "active"; at most
	// JournalActiveMax, newest first), and ActiveMatched how many match.
	// They are not records: each gets its one record when it ends.
	Active        []ConnRecord `json:"active,omitempty"`
	ActiveMatched int          `json:"active_matched,omitempty"`
}

// JournalActiveMax bounds JournalPage.Active.
const JournalActiveMax = 50

// ErrNamesNotRecorded refuses a text search when names are not recorded.
var ErrNamesNotRecorded = errors.New("names are not recorded: a text search has nothing to match")

// segSnap is a segment as a reader sees it.
type segSnap struct {
	path string
	size int64
}

// snapshot flushes nothing (each batch is one write) and lists the
// segments with their current sizes, newest last.
func (j *Journal) snapshot() []segSnap {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]segSnap, len(j.segs))
	for i, s := range j.segs {
		out[i] = segSnap{s.path, s.size}
	}
	return out
}

// each calls fn for every visible record, newest first (at most
// MaxRecords, none older than MaxAge), until fn returns false. It reads
// without holding the writer's lock: closed segments are immutable and the
// active one is read up to the size it had.
func (j *Journal) each(fn func(r *JournalRecord) bool) {
	cutoff := j.now().Add(-j.cfg.MaxAge)
	seen := 0
	segs := j.snapshot()
	for i := len(segs) - 1; i >= 0; i-- {
		f, err := os.Open(segs[i].path)
		if err != nil {
			continue // deleted since (pruned or cleared)
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
			var r JournalRecord
			if json.Unmarshal(lines[k], &r) != nil || r.ID == 0 {
				continue
			}
			if r.EndTime().Before(cutoff) {
				continue
			}
			if seen++; seen > j.cfg.MaxRecords {
				return
			}
			if !j.cfg.RecordNames {
				r.Name = ""
			}
			if !fn(&r) {
				return
			}
		}
	}
}

func (p parsedQuery) match(r *JournalRecord) bool {
	switch p.Result {
	case "":
	case ClassFailed:
		if !IsFailureClass(RecordClass(&r.ConnRecord)) {
			return false
		}
	case ClassNameUnresolved:
		if r.Why != WhyUnresolved {
			return false
		}
	default:
		if RecordClass(&r.ConnRecord) != p.Result {
			return false
		}
	}
	return p.matchConn(&r.ConnRecord)
}

// matchConn applies every filter but the result class (the active view's
// filter: an open connection has no result yet).
func (p parsedQuery) matchConn(r *ConnRecord) bool {
	if p.device.IsValid() {
		a, err := netip.ParseAddr(r.Source)
		if err != nil || a.Unmap() != p.device {
			return false
		}
	}
	if p.Target != "" && r.Target != p.Target {
		return false
	}
	if !p.from.IsZero() && r.EndTime().Before(p.from) {
		return false
	}
	if !p.to.IsZero() && !r.Start.Before(p.to) {
		return false
	}
	if p.text != "" && !strings.Contains(strings.ToLower(r.Name), p.text) {
		return false
	}
	return true
}

// Query answers one page, newest first.
func (j *Journal) Query(q JournalQuery) (JournalPage, error) {
	p, err := q.parse()
	if err != nil {
		return JournalPage{}, err
	}
	if p.text != "" && !j.cfg.RecordNames {
		return JournalPage{}, ErrNamesNotRecorded
	}
	page := JournalPage{RecordNames: j.cfg.RecordNames, Records: []JournalRecord{}}
	j.each(func(r *JournalRecord) bool {
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

// DeviceSummary is one client address in a summary.
type DeviceSummary struct {
	Device    string    `json:"device"`
	MAC       string    `json:"mac,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Total     int       `json:"total"`
	ByName    int       `json:"by_name"`
	ByAddress int       `json:"by_address"`
	// NameUnresolved: a name was read but gave no address (handled by
	// address).
	NameUnresolved int `json:"name_unresolved"`
	// Failed counts the records of a failure class (IsFailureClass).
	Failed int `json:"failed"`
	// ByClass counts each result class (RecordClass); ByEnd each end of a
	// relayed connection (EndClientClosed …); ByTarget each target (the
	// most frequent JournalSummaryTargets, the rest in OtherTargets).
	ByClass      map[string]int `json:"by_class"`
	ByEnd        map[string]int `json:"by_end,omitempty"`
	ByTarget     map[string]int `json:"by_target"`
	OtherTargets int            `json:"other_targets,omitempty"`
	// BytesUp / BytesDown sum the relayed bytes of the records.
	BytesUp   int64 `json:"bytes_up"`
	BytesDown int64 `json:"bytes_down"`
	// Active is the device's connections still being relayed (not in the
	// counts above; filled by the forwarder's status socket).
	Active int `json:"active,omitempty"`
}

// JournalSummary is the per-device summary.
type JournalSummary struct {
	RecordNames bool            `json:"record_names"`
	Devices     []DeviceSummary `json:"devices"`
	// Truncated: more devices than JournalSummaryDevices (the most
	// recently seen are listed).
	Truncated bool         `json:"truncated,omitempty"`
	Stats     JournalStats `json:"stats"`
}

// Validate checks a summary request.
func (q JournalSummaryQuery) Validate() error {
	_, _, err := parseRange(q.From, q.To)
	return err
}

// Summary aggregates the visible records per client address.
func (j *Journal) Summary(q JournalSummaryQuery) (JournalSummary, error) {
	from, to, err := parseRange(q.From, q.To)
	if err != nil {
		return JournalSummary{}, err
	}
	by := map[string]*DeviceSummary{}
	const maxTracked = 4096 // distinct addresses tracked while scanning
	j.each(func(r *JournalRecord) bool {
		end := r.EndTime()
		if (!from.IsZero() && end.Before(from)) || (!to.IsZero() && !r.Start.Before(to)) {
			return true
		}
		d := by[r.Source]
		if d == nil {
			if len(by) >= maxTracked {
				return true
			}
			d = &DeviceSummary{Device: r.Source, FirstSeen: r.Start, LastSeen: end, ByClass: map[string]int{}, ByEnd: map[string]int{}, ByTarget: map[string]int{}}
			by[r.Source] = d
		}
		d.Total++
		if r.Start.Before(d.FirstSeen) {
			d.FirstSeen = r.Start
		}
		if end.After(d.LastSeen) {
			d.LastSeen = end
		}
		if d.MAC == "" && r.MAC != "" {
			d.MAC = r.MAC // the newest record's MAC (newest first)
		}
		if r.Sniffed {
			d.ByName++
		} else {
			d.ByAddress++
		}
		if r.Why == WhyUnresolved {
			d.NameUnresolved++
		}
		cl := RecordClass(&r.ConnRecord)
		d.ByClass[cl]++
		if IsFailureClass(cl) {
			d.Failed++
		}
		if r.End != "" {
			d.ByEnd[r.End]++
		}
		d.BytesUp = clampCount(d.BytesUp + r.BytesUp)
		d.BytesDown = clampCount(d.BytesDown + r.BytesDown)
		if r.Target != "" {
			d.ByTarget[r.Target]++
		}
		return true
	})
	out := JournalSummary{RecordNames: j.cfg.RecordNames, Devices: []DeviceSummary{}}
	for _, d := range by {
		if len(d.ByTarget) > JournalSummaryTargets {
			type kv struct {
				k string
				n int
			}
			var all []kv
			for k, n := range d.ByTarget {
				all = append(all, kv{k, n})
			}
			sort.Slice(all, func(a, b int) bool { return all[a].n > all[b].n || all[a].n == all[b].n && all[a].k < all[b].k })
			d.ByTarget = map[string]int{}
			for i, x := range all {
				if i < JournalSummaryTargets {
					d.ByTarget[x.k] = x.n
				} else {
					d.OtherTargets += x.n
				}
			}
		}
		out.Devices = append(out.Devices, *d)
	}
	sort.Slice(out.Devices, func(a, b int) bool {
		da, db := out.Devices[a], out.Devices[b]
		return da.LastSeen.After(db.LastSeen) || da.LastSeen.Equal(db.LastSeen) && da.Device < db.Device
	})
	if len(out.Devices) > JournalSummaryDevices {
		out.Devices, out.Truncated = out.Devices[:JournalSummaryDevices], true
	}
	out.Stats = j.Stats()
	return out, nil
}
