package dnsjournal

// The reader of the resolver's audit file.
//
// It only ever reads (and, to hold the byte budget and the age bound or on
// "clear", unlinks and truncates) regular files in RawDir: nothing it does
// can make the resolver wait. Each Step (once a second in the daemon):
//
//   - follows the audit file from its saved position, at most
//     maxStepBytes per step (a flood makes the reader fall behind and lose
//     lines, never use more memory or queue);
//   - survives rotation: it keeps the file open, so after the resolver
//     renamed it away the rest is read from the open file before the new
//     one is opened at 0 (a remainder larger than one step is given up and
//     counted, so an unlinked file is never held for long);
//   - survives truncation (the resolver truncated its file to 0 on a full
//     filesystem; the reader truncates it itself for "clear", for the byte
//     budget and for the age bound — the observed resolver appends, so its
//     next line starts the file again): a file shorter than the position is
//     read from 0;
//   - survives its own restart: the position (inode, offset, the last
//     line's timestamp) is saved next to the segments; when the audit file
//     was rotated while the reader was down, the lines newer than the last
//     one read are taken from the gzip-compressed rotated files (the newest
//     catchUpMax of them);
//   - gives every parsed line its real time: the line's timestamp has no
//     zone (the resolver container's clock zone need not be the host's), so
//     the offset is taken from the audit file's own modification time
//     against its last line, rounded to a quarter of an hour, whenever the
//     reader is at the end of the file. Without an offset a record gets the
//     time it was read and says so (Record.TimeApprox);
//   - looks the client's MAC up in the kernel neighbour table only for a
//     line that is fresh (FreshFor): for an older line the table says
//     nothing about that moment and the MAC stays unknown;
//   - keeps RawDir inside Budget.Raw whatever the resolver does: the oldest
//     rotated copies are deleted first, and if the audit file alone is over
//     the budget it is truncated (counted; the resolver's own rotation at
//     AuditSizeKB normally keeps it far below);
//   - keeps nothing in RawDir longer than MaxAge (the journal's own age
//     bound; without this a quiet resolver never fills a file, never
//     rotates, and its queries would stay here long after their records
//     expired). A rotated copy (or any other file) is deleted once it was
//     last written longer ago than MaxAge, and already when its first line
//     is that old: nothing reads it again after the catch-up of the first
//     open, which comes before this in the same Step. The audit file
//     itself is truncated — never removed or replaced: it stays the regular
//     file the resolver has open — once its first line is older than
//     MaxAge and every byte of it has been read, so nothing that is still
//     to be ingested goes with it (see expireActive for the exact rule and
//     the one window that is left);
//   - keeps RawDir 0700 and every regular file in it 0600 (the resolver
//     sets its audit file to 0640 whenever it opens it, at start and after
//     a rotation, so it is 0640 until the next step), and removes anything
//     that is not a regular file.
//
// A line that does not parse is counted (TailStats.Bad) and nothing of it
// is kept, printed or logged.
//
// "Clear" (Tailer.Clear) deletes the copies and empties the audit file, and
// says what it could not: a failed listing, look, unlink or truncation is
// reported, never passed over. What it leaves is never ingested later:
//
//   - an audit file that could not be emptied is followed from where it
//     ended at the clear (never again from its start), and the saved
//     position says so, so a restart does the same;
//   - the lines of a copy that could not be deleted are not taken by the
//     catch-up after a restart: a copy last written before the clear is not
//     opened at all, and of any other copy only the lines written after the
//     clear are taken. That needs the zone of the timestamps: while it is
//     unknown and a clear is pending, the catch-up takes nothing at all
//     (the copies are counted as skipped) rather than risk an old line;
//   - the clear is remembered (the position file) for as long as something
//     it should have removed is still in the directory, and the reader
//     reports how much (TailStats.ClearPendingAt, RawResidualFiles,
//     RawResidualBytes): files last written before the clear, the copy the
//     un-emptied audit file became when the resolver rotated it, a rotated
//     copy whose first line is older than the clear (zone known), and the
//     un-emptied audit file itself. The age bound and the byte budget
//     delete them as they delete everything else; once nothing of it is
//     left the reminder goes. A compressed copy of the un-emptied audit
//     file is only recognised by its first line, so it is not counted as
//     residue while the zone is unknown (it is still never ingested, and
//     goes with the age bound or the next clear).

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"syscall"
	"time"
)

const (
	// maxStepBytes bounds what one Step reads.
	maxStepBytes = 256 << 10
	// catchUpMax bounds the lines taken from rotated files at start;
	// catchUpRead what is decompressed from one of them.
	catchUpMax  = 1500
	catchUpRead = 8 << 20
	// DefaultFreshFor is how old a line may be for its MAC to be looked up.
	DefaultFreshFor = 30 * time.Second
	// positionEvery is the period the position is saved at while it moves.
	positionEvery = 5 * time.Second
	// headScan bounds what is read of a file to find its first audit line.
	headScan = 4 * MaxRawLine
)

var rotatedRe = regexp.MustCompile(`^audit\.log-\d{8}-\d{6}(\.gz)?$`)

// TailConfig configures a Tailer.
type TailConfig struct {
	// Dir is the raw directory (RawDir).
	Dir string
	// PositionPath is where the position is saved ("" nowhere).
	PositionPath string
	// MaxRawBytes bounds everything in Dir (Budget.Raw).
	MaxRawBytes int64
	// MaxAge bounds how long anything stays in Dir (the journal's MaxAge);
	// 0 means DefaultMaxAge.
	MaxAge time.Duration
	// Lookup returns a client's MAC ("" unknown); nil: no lookup.
	Lookup func(netip.Addr) string
	// Emit takes one record (Journal.Add: it never blocks).
	Emit func(Record)
	// FreshFor: 0 means DefaultFreshFor. Now: nil means time.Now.
	FreshFor time.Duration
	Now      func() time.Time
	// Fault: tests only (the file-system calls of Clear).
	Fault Fault
}

// TailStats describes the reader. Every text in it is a fixed message.
type TailStats struct {
	Following bool `json:"following"`
	// Lines: complete lines read; Parsed: audit lines; Bad: lines that are
	// not audit lines; TooLong: lines over MaxRawLine.
	Lines   uint64 `json:"lines"`
	Parsed  uint64 `json:"parsed"`
	Bad     uint64 `json:"bad_lines"`
	TooLong uint64 `json:"too_long"`
	// Rotations and Truncations of the audit file seen; SkippedBytes given
	// up in a rotated file that could not be read within a step.
	Rotations    uint64 `json:"rotations"`
	Truncations  uint64 `json:"truncations"`
	SkippedBytes int64  `json:"skipped_bytes"`
	// CaughtUp: lines taken from rotated files at start; CatchUpSkipped:
	// newer lines there beyond catchUpMax; SkippedRotated: rotated files not
	// read at start because there was no saved position.
	CaughtUp       uint64 `json:"caught_up"`
	CatchUpSkipped uint64 `json:"catch_up_skipped"`
	SkippedRotated uint64 `json:"skipped_rotated"`
	// RawBytes / RawFiles: the regular files in the raw directory now.
	RawBytes    int64 `json:"raw_bytes"`
	RawFiles    int   `json:"raw_files"`
	RawMaxBytes int64 `json:"raw_max_bytes"`
	// RawDeleted: rotated copies deleted to hold the budget; RawTruncated:
	// times the audit file itself was truncated for it; SpecialRemoved:
	// entries removed because they were not regular files.
	RawDeleted     uint64 `json:"raw_deleted"`
	RawTruncated   uint64 `json:"raw_truncated"`
	SpecialRemoved uint64 `json:"special_removed"`
	// RawExpired: rotated copies (and other files) deleted because they
	// were older than MaxAge; RawAgeTruncated: times the audit file was
	// truncated for the same reason, after all of it had been read (unlike
	// RawTruncated, nothing unread is given up).
	RawExpired      uint64 `json:"raw_expired,omitempty"`
	RawAgeTruncated uint64 `json:"raw_age_truncated,omitempty"`
	// ZoneOffsetS is the offset of the audit timestamps from UTC as last
	// established (nil: never); TimeApprox the records that got the time
	// they were read instead.
	ZoneOffsetS *int   `json:"zone_offset_s,omitempty"`
	TimeApprox  uint64 `json:"time_approx"`
	// NoMAC: records without a MAC.
	NoMAC      uint64     `json:"no_mac"`
	LastReadAt *time.Time `json:"last_read_at,omitempty"`
	LastError  string     `json:"last_error,omitempty"`
	// ClearPendingAt: a clear at this time could not remove everything from
	// the raw directory and some of it is still there (nil: nothing is).
	// RawResidualFiles / RawResidualBytes: what is recognised of it now
	// (they are part of RawFiles / RawBytes). The next clear tries again.
	ClearPendingAt   *time.Time `json:"clear_pending_at,omitempty"`
	RawResidualFiles int        `json:"raw_residual_files,omitempty"`
	RawResidualBytes int64      `json:"raw_residual_bytes,omitempty"`
}

type position struct {
	Ino         uint64 `json:"ino"`
	Offset      int64  `json:"offset"`
	LastNaiveMS int64  `json:"last_naive_ms"`
	// Head: a digest of the file's first bytes (up to Offset): an inode
	// number alone may be reused by a new audit file after rotation
	// (empty in positions written by older versions: the inode is trusted).
	Head  string `json:"head,omitempty"`
	ZoneS *int   `json:"zone_s,omitempty"`
	// ClearMS: when a clear left something in the raw directory (0: none).
	// ClearIno / ClearOff: the audit file it could not empty and how long
	// that file was then (0: the audit file was emptied).
	ClearMS  int64  `json:"clear_ms,omitempty"`
	ClearIno uint64 `json:"clear_ino,omitempty"`
	ClearOff int64  `json:"clear_off,omitempty"`
}

// positionMax bounds the position file.
const positionMax = 1024

// writePosition replaces the position file at path.
func writePosition(path string, p position) error {
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// Tailer follows the audit file of one resolver.
type Tailer struct {
	cfg TailConfig

	mu        sync.Mutex
	started   bool
	pos       *position // the saved position, until the first open used it
	f         *os.File
	ino       uint64
	off       int64
	partial   []byte
	skipping  bool
	lastNaive time.Time
	zone      *time.Duration
	st        TailStats
	posDirty  bool
	posSaved  time.Time

	// since: when this reader opened the open file or last saw it empty.
	// What the file held then is older than that and what was written
	// later is newer, so from since + MaxAge on the file may hold
	// something older than MaxAge whatever its timestamps say.
	since time.Time
	// head: the timestamp of the first audit line of the open file (zero:
	// none found), once headRead.
	head     time.Time
	headRead bool
	// copies: what is known of the other files in the raw directory.
	copies map[rawCopyKey]*rawCopy

	// clearAt: a clear at this time left something in the raw directory
	// (zero: nothing is left of one). clearIno / clearOff: the audit file it
	// could not empty and its length then (0: none) — those bytes are
	// residue for as long as that file holds them.
	clearAt  time.Time
	clearIno uint64
	clearOff int64
	// clearLeft: the entries that clear failed on, by name (this process
	// only; after a restart they are recognised by the rules of isResidue).
	clearLeft map[string]bool
}

type rawCopyKey struct {
	name string
	ino  uint64
}

// rawCopy is a file in the raw directory that is not the audit file.
type rawCopy struct {
	first time.Time // when this reader first saw it
	size  int64     // the size its first line was read at (-1: not yet)
	head  time.Time // its first audit line's timestamp (zero: none found)
}

// NewTailer returns a reader; nothing is opened before the first Step.
func NewTailer(cfg TailConfig) *Tailer {
	if cfg.FreshFor <= 0 {
		cfg.FreshFor = DefaultFreshFor
	}
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = DefaultMaxAge
	}
	return &Tailer{cfg: cfg, st: TailStats{RawMaxBytes: cfg.MaxRawBytes}}
}

func (t *Tailer) now() time.Time {
	if t.cfg.Now != nil {
		return t.cfg.Now()
	}
	return time.Now()
}

func (t *Tailer) path() string { return filepath.Join(t.cfg.Dir, AuditBase) }

func inoOf(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Ino)
	}
	return 0
}

// Stats describes the reader now.
func (t *Tailer) Stats() TailStats {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.st
	st.Following = t.f != nil
	if t.zone != nil {
		s := int(*t.zone / time.Second)
		st.ZoneOffsetS = &s
	}
	if !t.clearAt.IsZero() {
		at := t.clearAt
		st.ClearPendingAt = &at
	}
	return st
}

// Step does one round of reading and housekeeping.
func (t *Tailer) Step() {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	if !t.started {
		t.started = true
		t.loadPosition()
	}
	budget := int64(maxStepBytes)
	for i := 0; i < 8 && budget > 0; i++ {
		if t.f == nil && !t.open(now) {
			break
		}
		n, eof := t.read(now, budget)
		budget -= n
		if t.f == nil {
			break
		}
		if !eof {
			continue
		}
		if !t.rotatedAway() {
			break
		}
		t.st.Rotations++
		t.closeFile()
	}
	if t.f != nil && budget <= 0 && t.rotatedAway() {
		// More of a rotated file than one step reads: give the rest up, so
		// an unlinked file is not held open across steps.
		if fi, err := t.f.Stat(); err == nil && fi.Size() > t.off {
			t.st.SkippedBytes += fi.Size() - t.off
		}
		t.st.Rotations++
		t.closeFile()
	}
	t.housekeep(now)
	t.savePosition(now, false)
}

// Close saves the position and closes the audit file.
func (t *Tailer) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.savePosition(t.now(), true)
	if t.f != nil {
		_ = t.f.Close()
		t.f = nil
	}
}

func (t *Tailer) closeFile() {
	if t.f != nil {
		_ = t.f.Close()
	}
	t.f, t.ino, t.off, t.partial, t.skipping = nil, 0, 0, nil, false
	t.headRead = false
	t.posDirty = true
}

// rewind: the open file is empty now (it was truncated); reading starts at
// its beginning again.
func (t *Tailer) rewind(now time.Time) {
	if t.clearIno != 0 && t.ino == t.clearIno {
		// What a clear could not empty is gone now.
		t.clearIno, t.clearOff = 0, 0
	}
	t.off, t.partial, t.skipping = 0, nil, false
	t.since, t.headRead = now, false
	t.posDirty = true
}

func (t *Tailer) loadPosition() {
	if t.cfg.PositionPath == "" {
		return
	}
	b, err := os.ReadFile(t.cfg.PositionPath)
	if err != nil || len(b) > positionMax {
		return
	}
	var p position
	if json.Unmarshal(b, &p) != nil || p.Offset < 0 {
		return
	}
	t.pos = &p
	if p.LastNaiveMS > 0 {
		t.lastNaive = time.UnixMilli(p.LastNaiveMS).UTC()
	}
	if p.ZoneS != nil && *p.ZoneS >= -14*3600 && *p.ZoneS <= 14*3600 {
		z := time.Duration(*p.ZoneS) * time.Second
		t.zone = &z
	}
	if p.ClearMS > 0 {
		t.clearAt = time.UnixMilli(p.ClearMS)
		if p.ClearIno != 0 && p.ClearOff > 0 {
			t.clearIno, t.clearOff = p.ClearIno, p.ClearOff
		}
	}
}

func (t *Tailer) savePosition(now time.Time, force bool) {
	if t.cfg.PositionPath == "" || !t.posDirty || (!force && now.Sub(t.posSaved) < positionEvery && !t.posSaved.IsZero()) {
		return
	}
	p := position{Ino: t.ino, Offset: t.off - int64(len(t.partial))}
	if p.Offset < 0 || t.skipping {
		p.Offset = t.off
	}
	if t.f == nil && t.pos != nil {
		// Nothing is open: where the next open is to start (the position
		// loaded at start, or the one a clear left) is what must survive.
		p.Ino, p.Offset, p.Head = t.pos.Ino, t.pos.Offset, t.pos.Head
	} else if t.f != nil {
		p.Head = headOf(t.f, p.Offset)
	}
	if !t.lastNaive.IsZero() {
		p.LastNaiveMS = t.lastNaive.UnixMilli()
	}
	if t.zone != nil {
		s := int(*t.zone / time.Second)
		p.ZoneS = &s
	}
	if !t.clearAt.IsZero() {
		p.ClearMS, p.ClearIno, p.ClearOff = t.clearAt.UnixMilli(), t.clearIno, t.clearOff
	}
	if writePosition(t.cfg.PositionPath, p) != nil {
		return
	}
	t.posDirty, t.posSaved = false, now
}

// open opens the audit file (a regular file only; never following a link,
// never blocking on a special file) and chooses where to start.
func (t *Tailer) open(now time.Time) bool {
	f, err := os.OpenFile(t.path(), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if os.IsNotExist(err) {
			t.st.LastError = "audit file does not exist"
		} else {
			t.st.LastError = "audit file cannot be opened"
		}
		return false
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		f.Close()
		t.st.LastError = "audit file is not a regular file"
		return false
	}
	t.f, t.ino, t.off, t.partial, t.skipping = f, inoOf(fi), 0, nil, false
	t.since, t.headRead = now, false
	t.st.LastError = ""
	if p := t.pos; p != nil {
		t.pos = nil
		switch {
		case p.Ino == t.ino && p.Ino != 0 && fi.Size() >= p.Offset && (p.Head == "" || headOf(f, p.Offset) == p.Head):
			t.off = p.Offset
		case (p.Ino != t.ino || (p.Head != "" && headOf(f, p.Offset) != p.Head)) && p.LastNaiveMS > 0:
			// Rotated while the reader was down (a reused inode number
			// with other contents is another file).
			// Rotated while the reader was down.
			t.catchUp(now)
		}
	} else if !t.everOpened() {
		// A first start without a position: rotated files are older than
		// anything this reader was asked to keep.
		t.st.SkippedRotated += uint64(len(t.rotatedFiles()))
	}
	t.posDirty = true
	return true
}

// headLen bounds the bytes position.Head digests.
const headLen = 256

// headOf digests the first min(off, headLen) bytes of f ("" when they cannot
// all be read: then they differ from any recorded head).
func headOf(f *os.File, off int64) string {
	n := min(off, headLen)
	b := make([]byte, n)
	if k, _ := f.ReadAt(b, 0); int64(k) != n {
		return "-"
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
}

// everOpened: the reader has read something before (in this process).
func (t *Tailer) everOpened() bool {
	return t.st.Lines > 0 || t.st.Rotations > 0 || !t.lastNaive.IsZero()
}

// rotatedAway: the audit path no longer names the open file.
func (t *Tailer) rotatedAway() bool {
	fi, err := os.Lstat(t.path())
	return err != nil || inoOf(fi) != t.ino
}

// read reads up to budget bytes at the position; eof says the position is
// at the end of the file.
func (t *Tailer) read(now time.Time, budget int64) (int64, bool) {
	fi, err := t.f.Stat()
	if err != nil {
		t.st.LastError = "audit file cannot be read"
		t.closeFile()
		return 0, true
	}
	size := fi.Size()
	if size < t.off {
		t.st.Truncations++
		t.rewind(now)
	}
	want := min(size-t.off, budget)
	if want <= 0 {
		return 0, true
	}
	buf := make([]byte, want)
	n, err := t.f.ReadAt(buf, t.off)
	if n <= 0 {
		if err != nil && err != io.EOF {
			t.st.LastError = "audit file cannot be read"
		}
		return 0, true
	}
	t.off += int64(n)
	t.posDirty = true
	t.st.LastReadAt = &now
	raws := t.feed(buf[:n])
	eof := t.off >= size
	t.emit(raws, fi.ModTime(), eof, now, true)
	return int64(n), eof
}

// feed splits b into lines (with what was left of the previous read) and
// parses them.
func (t *Tailer) feed(b []byte) []Raw {
	var out []Raw
	for len(b) > 0 {
		nl := bytes.IndexByte(b, '\n')
		if nl < 0 {
			switch {
			case t.skipping:
			case len(t.partial)+len(b) > MaxRawLine:
				t.partial, t.skipping = nil, true
			default:
				t.partial = append(t.partial, b...)
			}
			return out
		}
		seg := b[:nl]
		b = b[nl+1:]
		t.st.Lines++
		if t.skipping {
			t.skipping = false
			t.st.TooLong++
			continue
		}
		line := seg
		if len(t.partial) > 0 {
			line = append(append(make([]byte, 0, len(t.partial)+len(seg)), t.partial...), seg...)
			t.partial = nil
		}
		if len(line) > MaxRawLine {
			t.st.TooLong++
			continue
		}
		r, err := ParseLine(bytes.TrimRight(line, "\r"))
		if err != nil {
			t.st.Bad++
			continue
		}
		t.st.Parsed++
		out = append(out, r)
	}
	return out
}

// estimateZone: the offset of naive timestamps from UTC, from a file's last
// line (read as UTC) and the file's modification time: a multiple of a
// quarter of an hour within ±14 h, when the line and the write are at most
// five minutes apart.
func estimateZone(lastNaive, mtime time.Time) (time.Duration, bool) {
	d := lastNaive.Sub(mtime)
	off := d.Round(15 * time.Minute)
	if off < -14*time.Hour || off > 14*time.Hour {
		return 0, false
	}
	if r := d - off; r < -5*time.Minute || r > 5*time.Minute {
		return 0, false
	}
	return off, true
}

// emit turns parsed lines into records. atEnd: the lines end at the end of
// the file whose modification time is mtime (the zone offset is then
// re-established). live: the MAC may be looked up for fresh lines.
func (t *Tailer) emit(raws []Raw, mtime time.Time, atEnd bool, now time.Time, live bool) {
	if len(raws) == 0 {
		return
	}
	if atEnd {
		if z, ok := estimateZone(raws[len(raws)-1].Naive, mtime); ok {
			t.zone = &z
		}
	}
	for _, r := range raws {
		rec := Record{Client: r.Client.String(), Name: r.Name, QType: r.QType, Result: Classify(r.Answers, r.Other, r.Elapsed),
			Group: r.Group, ElapsedMS: r.Elapsed, Answers: r.Answers, AnswersOther: r.Other}
		fresh := false
		if t.zone != nil {
			rec.Time = r.Naive.Add(-*t.zone).UTC()
			age := now.Sub(rec.Time)
			fresh = age <= t.cfg.FreshFor && age >= -t.cfg.FreshFor
		} else {
			rec.Time, rec.TimeApprox = now.UTC(), true
			t.st.TimeApprox++
			fresh = atEnd
		}
		if live && fresh && t.cfg.Lookup != nil {
			rec.MAC = NormMAC(t.cfg.Lookup(r.Client))
		}
		if rec.MAC == "" {
			t.st.NoMAC++
		}
		if r.Naive.After(t.lastNaive) {
			t.lastNaive = r.Naive
		}
		if t.cfg.Emit != nil {
			t.cfg.Emit(rec)
		}
	}
}

func (t *Tailer) rotatedFiles() []string {
	ents, err := os.ReadDir(t.cfg.Dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if rotatedRe.MatchString(e.Name()) && e.Type().IsRegular() {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

// ReadRotated reads the lines of a rotated audit file (gzip-compressed or
// not), at most limit bytes of content.
func ReadRotated(path string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return nil, os.ErrInvalid
	}
	var r io.Reader = f
	if filepath.Ext(path) == ".gz" {
		zr, err := gzip.NewReader(f)
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		r = zr
	}
	b, err := io.ReadAll(io.LimitReader(r, limit))
	if err != nil && len(b) == 0 {
		return nil, err
	}
	return b, nil // a truncated archive still gives its readable part
}

// catchUp takes, from the rotated files, the lines newer than the last one
// read before the restart (the newest catchUpMax of them).
func (t *Tailer) catchUp(now time.Time) {
	since := t.lastNaive
	var all []Raw
	var mtime time.Time
	files := t.rotatedFiles()
	if !t.clearAt.IsZero() && t.zone == nil {
		// A clear left something here and the lines cannot be told apart
		// by their time: none is taken, rather than one from before it.
		t.st.SkippedRotated += uint64(len(files))
		return
	}
	for _, name := range files {
		p := filepath.Join(t.cfg.Dir, name)
		fi, lerr := os.Lstat(p)
		if lerr == nil && t.catchUpSkips(fi) {
			continue
		}
		b, err := ReadRotated(p, catchUpRead)
		if err != nil {
			continue
		}
		if lerr == nil {
			mtime = fi.ModTime()
		}
		for _, line := range bytes.Split(b, []byte{'\n'}) {
			if len(line) == 0 {
				continue
			}
			r, err := ParseLine(bytes.TrimRight(line, "\r"))
			if err != nil {
				t.st.Bad++
				continue
			}
			if !r.Naive.After(since) {
				continue
			}
			if !t.clearAt.IsZero() && t.zone != nil && !r.Naive.Add(-*t.zone).After(t.clearAt) {
				continue // written before a clear that could not delete this copy
			}
			all = append(all, r)
		}
	}
	if len(all) > catchUpMax {
		t.st.CatchUpSkipped += uint64(len(all) - catchUpMax)
		all = all[len(all)-catchUpMax:]
	}
	t.st.CaughtUp += uint64(len(all))
	t.emit(all, mtime, !mtime.IsZero(), now, false)
}

// catchUpSkips: a rotated copy the catch-up does not open while a clear
// that left something is pending: it was last written before that clear,
// so all of it is what the clear was to delete. (Of a copy written since,
// catchUp drops the lines from before the clear by their time.)
func (t *Tailer) catchUpSkips(fi os.FileInfo) bool {
	return !t.clearAt.IsZero() && !fi.ModTime().After(t.clearAt)
}

// isResidue: a file of the raw directory that is not the audit file is
// (or holds) something the pending clear was to delete: the clear failed on
// it; it was last written before the clear; it is the audit file the clear
// could not empty, rotated since; or its first line is older than the
// clear (a rotated copy, zone known; c.head as copyExpired read it).
func (t *Tailer) isResidue(c *rawCopy, name string, fi os.FileInfo) bool {
	switch {
	case t.clearAt.IsZero():
		return false
	case t.clearLeft[name], !fi.ModTime().After(t.clearAt):
		return true
	case t.clearIno != 0 && inoOf(fi) == t.clearIno:
		return true
	}
	return t.zone != nil && c.size == fi.Size() && !c.head.IsZero() && c.head.Add(-*t.zone).Before(t.clearAt)
}

// firstNaive is the timestamp of the first audit line in b (zero: none);
// only lines that end in b count.
func firstNaive(b []byte) time.Time {
	for {
		nl := bytes.IndexByte(b, '\n')
		if nl < 0 {
			return time.Time{}
		}
		if r, err := ParseLine(bytes.TrimRight(b[:nl], "\r")); err == nil {
			return r.Naive
		}
		b = b[nl+1:]
	}
}

// truncateRegular empties the file at path if it is a regular file, without
// following a link and without waiting on a special file. With ino != 0 it
// must be that file, and with size >= 0 exactly that long (nothing was
// appended since it was read to there).
func truncateRegular(path string, ino uint64, size int64) error {
	f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() || (ino != 0 && inoOf(fi) != ino) || (size >= 0 && fi.Size() != size) {
		return os.ErrInvalid
	}
	return f.Truncate(0)
}

// copyExpired: a file of the raw directory that is not the audit file holds
// something older than cutoff. Its content is at least as old as its last
// write and as the moment this reader first saw it; a rotated copy's first
// line is its oldest (read once per copy, and again if its size changed;
// usable only while the zone of the timestamps is known).
func (t *Tailer) copyExpired(c *rawCopy, name, path string, fi os.FileInfo, cutoff time.Time) bool {
	if fi.ModTime().Before(cutoff) || c.first.Before(cutoff) {
		return true
	}
	if t.zone == nil || !rotatedRe.MatchString(name) {
		return false
	}
	if c.size != fi.Size() {
		c.size, c.head = fi.Size(), time.Time{}
		if b, err := ReadRotated(path, headScan); err == nil {
			c.head = firstNaive(b)
		}
	}
	return !c.head.IsZero() && c.head.Add(-*t.zone).Before(cutoff)
}

// expireActive empties the audit file being followed when it holds
// something older than MaxAge, and returns the bytes that went. It never
// gives up a line that is still to be ingested:
//
//   - only when the reader is at the end of the file with no unfinished
//     line pending — every line in it has been handed on. (An unfinished
//     line no longer holds this up once the file has not been written for
//     MaxAge: nothing is going to finish it.)
//   - the file is emptied in place (the same regular file the resolver has
//     open for appending; never a link, never a special file), and only if
//     it is still the file that was read and still exactly as long as what
//     was read. What is left is the moment between that last look and the
//     truncation: a line the resolver appends right then is lost. There is
//     no way to close it without making the resolver wait.
//
// "Older than MaxAge" is any of: the file was last written longer ago (all
// of it is that old); its first audit line is that old by its own
// timestamp (needs the zone); this reader opened it, or last saw it empty,
// that long ago — the bound that holds whatever the timestamps and the file
// times say, for as long as the reader runs (time.Now carries the monotonic
// clock, so setting the host's clock does not move it). The position is
// saved at once, so a restart does not look for the old offset in the
// file's new content.
func (t *Tailer) expireActive(now time.Time) int64 {
	if t.f == nil {
		return 0
	}
	fi, err := t.f.Stat()
	if err != nil || fi.Size() != t.off {
		return 0
	}
	if t.off == 0 {
		// Empty: whatever is written into it from here on is newer than now.
		t.since = now
		return 0
	}
	cutoff := now.Add(-t.cfg.MaxAge)
	if !fi.ModTime().Before(cutoff) {
		if len(t.partial) > 0 || t.skipping {
			return 0
		}
		if !t.since.Before(cutoff) {
			if !t.headRead {
				t.headRead = true
				buf := make([]byte, min(t.off, headScan))
				n, _ := t.f.ReadAt(buf, 0)
				t.head = firstNaive(buf[:n])
			}
			if t.zone == nil || t.head.IsZero() || !t.head.Add(-*t.zone).Before(cutoff) {
				return 0
			}
		}
	}
	if truncateRegular(t.path(), t.ino, t.off) != nil {
		return 0
	}
	t.st.RawAgeTruncated++
	t.rewind(now)
	t.savePosition(now, true)
	return fi.Size()
}

// housekeep keeps the raw directory's modes, its byte budget and its age
// bound.
func (t *Tailer) housekeep(now time.Time) {
	if fi, err := os.Lstat(t.cfg.Dir); err == nil && fi.IsDir() && fi.Mode().Perm() != 0o700 {
		_ = os.Chmod(t.cfg.Dir, 0o700)
	}
	ents, err := os.ReadDir(t.cfg.Dir)
	if err != nil {
		return
	}
	type file struct {
		name string
		size int64
	}
	var rotated, other []file
	var active *file
	var total int64
	n := 0
	cutoff := now.Add(-t.cfg.MaxAge)
	copies := make(map[rawCopyKey]*rawCopy, len(t.copies))
	// What is left of a pending clear (see isResidue): counted in this
	// pass; resUnseen: an entry could not be looked at.
	var resFiles int
	var resBytes int64
	resUnseen, clearInoSeen := false, false
	residue := map[string]int64{}
	for _, e := range ents {
		p := filepath.Join(t.cfg.Dir, e.Name())
		fi, err := os.Lstat(p)
		if err != nil {
			resUnseen = resUnseen || !os.IsNotExist(err)
			continue
		}
		switch {
		case fi.IsDir():
			continue
		case !fi.Mode().IsRegular():
			if os.Remove(p) == nil {
				t.st.SpecialRemoved++
			}
			continue
		}
		if fi.Mode().Perm() != 0o600 {
			_ = os.Chmod(p, 0o600)
		}
		f := file{e.Name(), fi.Size()}
		if e.Name() != AuditBase {
			k := rawCopyKey{e.Name(), inoOf(fi)}
			c := t.copies[k]
			if c == nil {
				c = &rawCopy{first: now, size: -1}
			}
			if t.copyExpired(c, e.Name(), p, fi, cutoff) && os.Remove(p) == nil {
				t.st.RawExpired++
				continue
			}
			copies[k] = c
			if t.isResidue(c, e.Name(), fi) {
				residue[e.Name()] = fi.Size()
			}
			clearInoSeen = clearInoSeen || (t.clearIno != 0 && k.ino == t.clearIno)
		} else if t.clearIno != 0 && inoOf(fi) == t.clearIno {
			// The audit file a clear could not empty: what it held then is
			// residue until the file is emptied (shorter than it was).
			if clearInoSeen = fi.Size() >= t.clearOff; clearInoSeen {
				resFiles++
				resBytes += t.clearOff
			}
		}
		n++
		total += fi.Size()
		switch {
		case e.Name() == AuditBase:
			active = &f
		case rotatedRe.MatchString(e.Name()):
			rotated = append(rotated, f)
		default:
			other = append(other, f)
		}
	}
	t.copies = copies
	if lim := t.cfg.MaxRawBytes; lim > 0 && total > lim {
		sort.Slice(rotated, func(a, b int) bool { return rotated[a].name < rotated[b].name })
		for _, f := range append(rotated, other...) {
			if total <= lim {
				break
			}
			if os.Remove(filepath.Join(t.cfg.Dir, f.name)) == nil {
				total -= f.size
				n--
				t.st.RawDeleted++
				delete(residue, f.name)
			}
		}
		if total > lim && active != nil {
			if truncateRegular(t.path(), 0, -1) == nil {
				total -= active.size
				active = nil
				t.st.RawTruncated++
				if t.f != nil {
					t.rewind(now)
				}
			}
		}
	}
	if active != nil {
		total -= t.expireActive(now)
	}
	t.st.RawBytes, t.st.RawFiles = total, n
	if t.clearAt.IsZero() {
		t.st.RawResidualFiles, t.st.RawResidualBytes = 0, 0
		return
	}
	if t.clearIno != 0 && !clearInoSeen && !resUnseen {
		// No file here is that audit file any more (the number may be
		// given to another file from now on).
		t.clearIno, t.clearOff = 0, 0
		t.posDirty = true
	}
	if t.clearIno == 0 && clearInoSeen {
		// Emptied in this very pass (rewind).
		resFiles, resBytes = 0, 0
	}
	left := map[string]bool{}
	for name, size := range residue {
		resFiles++
		resBytes += size
		if t.clearLeft[name] {
			left[name] = true
		}
	}
	t.clearLeft = left
	t.st.RawResidualFiles, t.st.RawResidualBytes = resFiles, resBytes
	if resFiles == 0 && !resUnseen {
		// Nothing the clear was to delete is left: it is not pending.
		t.clearAt, t.clearIno, t.clearOff, t.clearLeft = time.Time{}, 0, 0, nil
		t.posDirty = true
	}
}

// RawClear is what a clear of the raw directory did.
type RawClear struct {
	// Freed: the bytes removed.
	Freed int64
	// Files / Bytes: what should have gone and is still there.
	Files int
	Bytes int64
	// Unknown: the directory or an entry could not be looked at, so more
	// may be left than was counted.
	Unknown bool
	// Errors: why, as fixed words.
	Errors []ClearError
}

// Clear empties the raw side: the audit file is truncated (it stays the
// same regular file the resolver has open) and the rotated copies are
// deleted. Whatever fails is reported, and what is left is never ingested
// afterwards (see the top of this file).
func (t *Tailer) Clear() RawClear {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	if !t.started {
		// A clear before the first step: what was saved (the last line
		// read, the zone) is loaded now, not over what this clear decides.
		t.started = true
		t.loadPosition()
	}
	fs := t.cfg.Fault
	var res RawClear
	var errs clearErrs
	// left: the entries that are still there, and their bytes.
	left := map[string]int64{}
	// keep: where an audit file that was not emptied is followed from.
	var keep *position

	// The audit file first: when the resolver rotates right now, what it
	// renames away becomes a copy, and the copies are looked at afterwards.
	p := t.path()
	fi, err := fs.lstat(p)
	switch {
	case err != nil && os.IsNotExist(err):
	case err != nil:
		// It cannot even be looked at: whatever is open, or was to be
		// opened, is followed from its end and not from its start.
		errs.add(PartRaw, "lstat", err)
		res.Unknown = true
		switch {
		case t.f != nil:
			keep = &position{Ino: t.ino, Offset: t.off}
			if ofi, err := t.f.Stat(); err == nil {
				keep.Offset = ofi.Size()
			}
		case t.pos != nil:
			keep = &position{Ino: t.pos.Ino, Offset: t.pos.Offset}
		}
	case fi.IsDir():
	case !fi.Mode().IsRegular():
		// Never something the resolver may write to (housekeeping removes
		// it as well).
		if err := fs.remove(p); err != nil && !os.IsNotExist(err) {
			errs.add(PartRaw, "remove", err)
			left[AuditBase] = 0
		}
	case fi.Size() > 0:
		switch err := fs.truncate(p); {
		case err == nil:
			res.Freed += fi.Size()
		case os.IsNotExist(err):
			// Rotated away this instant: it is a copy now.
		default:
			errs.add(PartRaw, "truncate", err)
			left[AuditBase] = fi.Size()
			keep = &position{Ino: inoOf(fi), Offset: fi.Size()}
		}
	}

	// The copies (everything else that is not a directory). A pass that
	// removed something is followed by another look: the resolver may have
	// rotated meanwhile.
	for pass := 0; pass < 3; pass++ {
		ents, err := fs.readDir(t.cfg.Dir)
		if err != nil {
			if !os.IsNotExist(err) {
				errs.add(PartRaw, "readdir", err)
				res.Unknown = true
			}
			break
		}
		removed := false
		for _, e := range ents {
			name := e.Name()
			if _, failed := left[name]; failed || name == AuditBase {
				continue
			}
			ep := filepath.Join(t.cfg.Dir, name)
			efi, err := fs.lstat(ep)
			if err != nil {
				if !os.IsNotExist(err) {
					errs.add(PartRaw, "lstat", err)
					res.Unknown = true
					left[name] = 0
				}
				continue
			}
			if efi.IsDir() {
				continue
			}
			var size int64
			if efi.Mode().IsRegular() {
				size = efi.Size()
			}
			if err := fs.remove(ep); err != nil && !os.IsNotExist(err) {
				errs.add(PartRaw, "remove", err)
				left[name] = size
				continue
			}
			res.Freed += size
			removed = true
		}
		if !removed {
			break
		}
	}

	// Drop the open file outright: the resolver may have rotated since the
	// last read, so the handle can name a deleted file whose unread rest
	// would come back after the clear. The next step opens the audit file
	// again: from its start when it was emptied, from where it ended when
	// it was not.
	t.closeFile()
	t.pos = nil
	t.clearAt, t.clearIno, t.clearOff, t.clearLeft = time.Time{}, 0, 0, nil
	if keep != nil && keep.Ino != 0 {
		if !t.lastNaive.IsZero() {
			keep.LastNaiveMS = t.lastNaive.UnixMilli()
		}
		t.pos = keep
	}
	if len(left) > 0 || res.Unknown {
		t.clearAt = now
		if t.pos != nil && t.pos.Offset > 0 {
			t.clearIno, t.clearOff = t.pos.Ino, t.pos.Offset
		}
		t.clearLeft = make(map[string]bool, len(left))
		for name, size := range left {
			res.Files++
			res.Bytes += size
			t.clearLeft[name] = true
		}
	}
	t.posDirty = true
	t.savePosition(now, true)
	t.housekeep(now)
	res.Errors = errs.list()
	return res
}
