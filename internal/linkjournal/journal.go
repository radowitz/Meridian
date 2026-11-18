// Package linkjournal is the gateway's link journal (docs/architecture.md
// 「链路日志」): a bounded, restart-surviving record of state CHANGES of the
// gateway's paths and links — which path carries, a relay leaving or
// rejoining the sharing set, a tunnel's handshake going stale, a WSS
// carrier dropping, the gateway's own check of an exit failing — and never a
// series of samples.
//
// Three parts:
//
//   - sources.go: the fixed, read-only sources on the gateway (the source
//     inventory is documented there), each turned into Observations: "object
//     X is in state S now, because …";
//   - this file: the Journal, which turns successive Observations into
//     transition Events, keeps them inside three bounds and survives a
//     restart;
//   - daemon.go: "meridian link-journal", the collector process that samples
//     the sources and answers fixed requests on a status socket (uid 0 only:
//     the host agent).
//
// How Observations become Events:
//
//   - Baseline. The first reading of an object records its state without an
//     event: the journal cannot know when that state began ("open": it
//     lasted at least since then).
//   - Transition. A reading that differs from the recorded state is one
//     Event: time, object, from → to, the source's reason and evidence, and
//     how long the previous state was observed (PrevForS; PrevOpen when its
//     real length is longer or unknown).
//   - Gap. An object not read for longer than GapAfter (the collector was
//     stopped, the source did not answer, the clock stepped) has an unknown
//     state in between. No duration ever spans it: an unchanged state starts
//     counting again after the gap (open), a changed one is an Event marked
//     AfterGap whose previous duration ends at the last reading before the
//     gap. A gap of the whole collection is one Event of its own (class
//     "collector", from "unknown").
//   - Restart. Objects, their states and the open flap records are in a
//     checkpoint written with every Event and once a minute. After a restart
//     the first pass compares against it: an unchanged state is no Event
//     (no fake switch), whatever the length of the stop. Without a
//     checkpoint (first start, or after a clear) the first pass is a
//     baseline.
//   - Flapping. An object's first FlapAfter changes inside FlapWindow are
//     Events of their own; further changes are merged into ONE record that
//     keeps the count and the first and last time ("changed N times"), is
//     written when the object has been quiet for FlapQuiet (or after
//     FlapMax), and never reads as one continuous outage.
//   - Budget. On top of that, at most WritesPerHour Events are written per
//     hour; beyond it they are dropped and counted (the state is still
//     tracked).
//
// Bounds, first reached wins: MaxAge (30 days), MaxEvents (20000), MaxBytes
// (16 MiB). MaxBytes covers everything in the directory — the segment
// files, the checkpoint, its temporary copy during the atomic replace and
// the temporary copy of a segment being rewritten (SplitBudget).
//
// An Event holds topology names (link, node, group and interface names the
// gateway's own files already carry), state words and the source's reason.
// It never holds an address of a LAN device, a queried name, a destination
// or any other part of user traffic: no source reads any.
package linkjournal

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
)

// oNoFollow: the journal's files are never opened through a symbolic link.
const oNoFollow = syscall.O_NOFOLLOW

// Fixed names on the gateway.
const (
	// Unit is the collector's unit (compile.RenderLinkJournalUnit).
	Unit = "meridian-link-journal.service"
	// StateDirName is the unit's StateDirectory: StateDir, root only (0700),
	// files 0600.
	StateDirName = "meridian-linklog"
	StateDir     = "/var/lib/" + StateDirName
	// RuntimeDirName is the unit's RuntimeDirectory; StatusSocket answers
	// uid 0 only.
	RuntimeDirName = "meridian-link-journal"
	StatusSocket   = "/run/" + RuntimeDirName + "/status.sock"
	// ConfigPath is the compiled object list (compile.renderLinkJournalConfig).
	ConfigPath = "/etc/meridian/link-journal.json"
	// ReadyMarker is in every binary that has "meridian link-journal" (the
	// unit greps for it before starting, so an older binary cannot start the
	// panel in the collector's place).
	ReadyMarker = "meridian-link-journal-ready"
)

// Bounds and timing defaults.
const (
	DefaultMaxEvents = 20000
	DefaultMaxAge    = 30 * 24 * time.Hour
	// DefaultMaxBytes is the whole budget (SplitBudget).
	DefaultMaxBytes = 16 << 20
	// MaxLine bounds one stored event (JSON line, newline included).
	MaxLine = 1024
	// SegmentEvents bounds the events of one segment file; MaxSegments the
	// segment files.
	SegmentEvents = 512
	MaxSegments   = 96
	// MaxCheckpoint bounds the checkpoint file; MaxObjects the objects it
	// tracks.
	MaxCheckpoint = 256 << 10
	MaxObjects    = 600
	// PageDefault / PageMax: events per page.
	PageDefault = 100
	PageMax     = 500
	// MaxEvidence / MaxLabel bound the texts of an event (bytes).
	MaxEvidence = 420
	MaxLabel    = 96

	// DefaultGapAfter: an object not read for longer than this has an
	// unknown state in between.
	DefaultGapAfter = 2 * time.Minute
	// Flap merging: the first DefaultFlapAfter changes of one object inside
	// DefaultFlapWindow are single events; later ones are merged until the
	// object was quiet for DefaultFlapQuiet, at most DefaultFlapMax per
	// merged record.
	DefaultFlapWindow = 10 * time.Minute
	DefaultFlapAfter  = 4
	DefaultFlapQuiet  = 10 * time.Minute
	DefaultFlapMax    = time.Hour
	// DefaultWritesPerHour bounds the events written per hour over all
	// objects.
	DefaultWritesPerHour = 600
	// CheckpointEvery: the checkpoint is rewritten at least this often (its
	// "last pass" time is what a restart measures the gap from).
	CheckpointEvery = time.Minute
	// TrimEvery: how often expired events are removed from the oldest
	// segment (queries never return an expired event in between).
	TrimEvery = time.Hour

	blockSlack     = 4096
	segPrefix      = "events-"
	segSuffix      = ".jsonl"
	checkpointFile = "checkpoint.json"
	tmpSuffix      = ".tmp"
)

// Budget is the one byte budget split over everything in the directory.
type Budget struct {
	Total int64 `json:"total"`
	// Events: the segment files (one filesystem block of slack per file
	// included).
	Events int64 `json:"events"`
	// Checkpoint: the checkpoint file and its temporary copy during the
	// atomic replace.
	Checkpoint int64 `json:"checkpoint"`
	// Rewrite: the temporary copy of the one segment being rewritten when
	// expired events are removed.
	Rewrite int64 `json:"rewrite"`
}

// SplitBudget splits total (0: DefaultMaxBytes).
func SplitBudget(total int64) Budget {
	if total <= 0 {
		total = DefaultMaxBytes
	}
	b := Budget{Total: total, Checkpoint: 2 * (MaxCheckpoint + blockSlack), Rewrite: SegmentEvents*MaxLine + blockSlack}
	b.Events = total - b.Checkpoint - b.Rewrite
	return b
}

// MinBytes is the smallest budget the journal accepts.
const MinBytes = 4 << 20

// Event classes.
const (
	ClassPath         = "path"
	ClassRelay        = "relay"
	ClassTunnel       = "tunnel"
	ClassWSS          = "wss"
	ClassExternalExit = "external_exit"
	ClassSniffTarget  = "sniff_target"
	ClassCollector    = "collector"
)

// Object kinds of class "collector" and their states.
const (
	KindCollector = "collector"
	KindSource    = "source"
	KindConfig    = "config"
	// CollectorID is the one object of kind collector and of kind config.
	CollectorID = "gateway"

	StateUnknown     = "unknown"
	StateCollecting  = "collecting"
	StateSourceOK    = "ok"
	StateUnavailable = "unavailable"

	ReasonRestart = "restart"
	ReasonStall   = "stall"
	ReasonClock   = "clock"
	ReasonConfig  = "config_changed"
)

// Gap is a stretch without readings.
type Gap struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// Event is one state change (or one merged run of changes) of one object.
type Event struct {
	// Seq numbers the events in the order they were written.
	Seq uint64 `json:"seq"`
	// At is when the collector saw the change (second precision, UTC). For
	// a merged record it is the first of its changes and LastAt the last.
	At time.Time `json:"at"`
	// Class, Kind and ID name the object; Label says what it is (from the
	// compiled object list).
	Class string `json:"class"`
	Kind  string `json:"kind"`
	ID    string `json:"id"`
	Label string `json:"label,omitempty"`
	From  string `json:"from"`
	To    string `json:"to"`
	// Source is the fixed source the reading came from (sources.go);
	// Reason its machine reason, Evidence what was read, in words.
	Source   string `json:"source,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Evidence string `json:"evidence,omitempty"`
	// SourceAt is the source's own time for the change, when it has one
	// (the failover loop's "since", the self-check's end).
	SourceAt *time.Time `json:"source_at,omitempty"`
	// PrevForS: how long the previous state (From) was observed, in
	// seconds. PrevOpen: its real length is longer or unknown — it was
	// already there at the first reading, or it ended inside a gap.
	PrevForS *int64 `json:"prev_for_s,omitempty"`
	PrevOpen bool   `json:"prev_open,omitempty"`
	// AfterGap: the change was found after a stretch without readings; when
	// inside it the change happened is not known.
	AfterGap *Gap `json:"after_gap,omitempty"`
	// Changes > 1: a merged record. The object changed Changes times
	// between At and LastAt, from From (before the first) to To (after the
	// last). It is not one continuous state.
	Changes int        `json:"changes,omitempty"`
	LastAt  *time.Time `json:"last_at,omitempty"`
	// Open: a merged record still being counted (not yet written; only in
	// answers).
	Open bool `json:"open,omitempty"`
}

// Observation is one reading of one object by a source. An empty State
// means "no reading this pass".
type Observation struct {
	Class, Kind, ID string
	Label           string
	State           string
	Source          string
	Reason          string
	Evidence        string
	SourceAt        time.Time
}

// flap is an open merged record.
type flap struct {
	FirstAt  time.Time `json:"first_at"`
	LastAt   time.Time `json:"last_at"`
	Changes  int       `json:"changes"`
	From     string    `json:"from"`
	To       string    `json:"to"`
	Reason   string    `json:"reason,omitempty"`
	Evidence string    `json:"evidence,omitempty"`
	// First is the first change as a single event (written as such when the
	// record closes with one change only).
	First Event `json:"first"`
}

// object is the tracked state of one object (checkpointed).
type object struct {
	Class    string `json:"class"`
	Kind     string `json:"kind"`
	ID       string `json:"id"`
	Label    string `json:"label,omitempty"`
	Source   string `json:"source,omitempty"`
	State    string `json:"state"`
	Reason   string `json:"reason,omitempty"`
	Evidence string `json:"evidence,omitempty"`
	// Since: the first reading of State in the current unbroken run of
	// readings. Open: State began before Since (baseline, or after a gap).
	Since    time.Time  `json:"since"`
	Open     bool       `json:"open,omitempty"`
	LastSeen time.Time  `json:"last_seen"`
	SourceAt *time.Time `json:"source_at,omitempty"`
	// Recent: unix times of the object's last single events (flap window).
	Recent []int64 `json:"recent,omitempty"`
	Flap   *flap   `json:"flap,omitempty"`
}

func objKey(kind, id string) string { return kind + "\x00" + id }

type checkpoint struct {
	Version   int        `json:"version"`
	Digest    string     `json:"config_digest,omitempty"`
	WrittenAt time.Time  `json:"written_at"`
	LastPass  time.Time  `json:"last_pass"`
	Seq       uint64     `json:"seq"`
	NextSeq   uint64     `json:"next_seq"`
	ClearedAt *time.Time `json:"cleared_at,omitempty"`
	Objects   []*object  `json:"objects"`
}

// Options configures Open. Zero values take the defaults.
type Options struct {
	Dir       string
	MaxEvents int
	MaxAge    time.Duration
	// MaxBytes is the whole budget (SplitBudget).
	MaxBytes int64
	// Digest identifies the compiled object list the collector runs with.
	Digest string

	GapAfter      time.Duration
	FlapWindow    time.Duration
	FlapAfter     int
	FlapQuiet     time.Duration
	FlapMax       time.Duration
	WritesPerHour int
	// Now: tests only (nil: time.Now).
	Now func() time.Time
	// noSync skips fsync (the package's own tests on a fake clock write tens
	// of thousands of events).
	noSync bool
}

// Stats describes the journal.
type Stats struct {
	Events   int        `json:"events"`
	Bytes    int64      `json:"bytes"`
	Segments int        `json:"segments"`
	Objects  int        `json:"objects"`
	Oldest   *time.Time `json:"oldest,omitempty"`
	Newest   *time.Time `json:"newest,omitempty"`
	// DiskBytes: every regular file in the directory, as found now.
	DiskBytes int64 `json:"disk_bytes"`
	// Written counts events written since start; Merged changes folded into
	// merged records; DroppedBudget events not written because the hourly
	// write budget was used up; WriteErrors events lost to a failed write;
	// Trimmed events removed by a bound; BadLines unreadable lines skipped
	// when the journal was opened; ObjectsRefused readings of objects
	// beyond MaxObjects.
	Written        uint64 `json:"written"`
	Merged         uint64 `json:"merged"`
	DroppedBudget  uint64 `json:"dropped_budget"`
	WriteErrors    uint64 `json:"write_errors"`
	Trimmed        uint64 `json:"trimmed"`
	BadLines       uint64 `json:"bad_lines,omitempty"`
	ObjectsRefused uint64 `json:"objects_refused,omitempty"`
	OpenFlaps      int    `json:"open_flaps"`
	// CheckpointAt: the last checkpoint written; CheckpointError the last
	// failure to write one ("" none).
	CheckpointAt    *time.Time `json:"checkpoint_at,omitempty"`
	CheckpointError string     `json:"checkpoint_error,omitempty"`
	// Restored: this process started from a checkpoint. BaselineAt: when
	// the objects were first read without one (first start or after a
	// clear).
	Restored   bool       `json:"restored"`
	BaselineAt *time.Time `json:"baseline_at,omitempty"`
	LastPass   *time.Time `json:"last_pass,omitempty"`
	ClearedAt  *time.Time `json:"cleared_at,omitempty"`
	MaxEvents  int        `json:"max_events"`
	MaxAgeS    int64      `json:"max_age_s"`
	Budget     Budget     `json:"budget"`
	GapAfterS  int64      `json:"gap_after_s"`
	FlapAfter  int        `json:"flap_after"`
	FlapWinS   int64      `json:"flap_window_s"`
	FlapQuietS int64      `json:"flap_quiet_s"`
	WritesHour int        `json:"writes_per_hour"`
}

type segment struct {
	name        string
	first, last uint64
	count       int
	size        int64
	// oldest / newest: the earliest and the latest moment an event of the
	// segment speaks about (eventEnd).
	newest time.Time
	oldest time.Time
}

// Journal is the link journal of one gateway.
type Journal struct {
	cfg      Options
	budget   Budget
	segEv    int
	maxFill  int64
	mu       sync.Mutex
	events   []Event // sorted by (At, Seq)
	segs     []*segment
	f        *os.File
	nextSeq  uint64
	objs     map[string]*object
	lastPass time.Time
	fresh    bool // no pass yet in this process
	dirty    bool
	lastCP   time.Time
	lastTrim time.Time
	writes   []int64
	cpDigest string
	st       Stats
}

func trunc(t time.Time) time.Time { return t.UTC().Truncate(time.Second) }

func tp(t time.Time) *time.Time { return &t }

// Open opens (or creates) the journal in cfg.Dir: the segments are read
// back, the bounds applied and the checkpoint loaded.
func Open(cfg Options) (*Journal, error) {
	if cfg.Dir == "" || !filepath.IsAbs(cfg.Dir) || filepath.Clean(cfg.Dir) != cfg.Dir {
		return nil, fmt.Errorf("journal directory %q is not a clean absolute path", cfg.Dir)
	}
	if cfg.MaxEvents <= 0 {
		cfg.MaxEvents = DefaultMaxEvents
	}
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = DefaultMaxAge
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = DefaultMaxBytes
	}
	if cfg.MaxBytes < MinBytes {
		return nil, fmt.Errorf("journal byte budget %d is below %d", cfg.MaxBytes, MinBytes)
	}
	if cfg.GapAfter <= 0 {
		cfg.GapAfter = DefaultGapAfter
	}
	if cfg.FlapWindow <= 0 {
		cfg.FlapWindow = DefaultFlapWindow
	}
	if cfg.FlapAfter <= 0 {
		cfg.FlapAfter = DefaultFlapAfter
	}
	if cfg.FlapQuiet <= 0 {
		cfg.FlapQuiet = DefaultFlapQuiet
	}
	if cfg.FlapMax <= 0 {
		cfg.FlapMax = DefaultFlapMax
	}
	if cfg.WritesPerHour <= 0 {
		cfg.WritesPerHour = DefaultWritesPerHour
	}
	j := &Journal{cfg: cfg, budget: SplitBudget(cfg.MaxBytes), objs: map[string]*object{}, fresh: true, nextSeq: 1}
	// A segment holds at most an eighth of the event bound, so dropping the
	// oldest one never empties the journal.
	j.segEv = cfg.MaxEvents / 8
	if j.segEv < 1 {
		j.segEv = 1
	}
	if j.segEv > SegmentEvents {
		j.segEv = SegmentEvents
	}
	j.maxFill = j.budget.Events - blockSlack*(MaxSegments+2)
	if j.maxFill < 2*int64(j.segEv)*MaxLine {
		return nil, fmt.Errorf("journal byte budget %d is too small for two segments", cfg.MaxBytes)
	}
	if fi, err := os.Lstat(cfg.Dir); err == nil && (fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir()) {
		return nil, fmt.Errorf("%s is not a real directory", cfg.Dir)
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
	j.loadCheckpoint()
	now := j.now()
	j.enforce()
	j.trimAge(now, true)
	return j, nil
}

func (j *Journal) now() time.Time {
	if j.cfg.Now != nil {
		return trunc(j.cfg.Now())
	}
	return trunc(time.Now())
}

func segName(first uint64) string { return fmt.Sprintf("%s%020d%s", segPrefix, first, segSuffix) }

var segNameRe = regexp.MustCompile(`^events-(\d{20})\.jsonl$`)

// recover reads the segment files back. Temporary files of an interrupted
// write are removed; anything that is not a regular file is left alone and
// never read.
func (j *Journal) recover() error {
	ents, err := os.ReadDir(j.cfg.Dir)
	if err != nil {
		return err
	}
	var names []string
	for _, e := range ents {
		n := e.Name()
		fi, err := os.Lstat(filepath.Join(j.cfg.Dir, n))
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		switch {
		case strings.HasSuffix(n, tmpSuffix):
			_ = os.Remove(filepath.Join(j.cfg.Dir, n))
		case segNameRe.MatchString(n):
			names = append(names, n)
			_ = os.Chmod(filepath.Join(j.cfg.Dir, n), 0o600)
		}
	}
	sort.Strings(names)
	var last uint64
	clean := false
	for _, n := range names {
		sg := &segment{name: n}
		f, err := os.OpenFile(filepath.Join(j.cfg.Dir, n), os.O_RDONLY|oNoFollow, 0)
		if err != nil {
			// One unreadable segment loses its events, not the journal: the
			// collector must still start (its unit failing would fail the
			// gateway install that carries it).
			j.st.BadLines++
			clean = false
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, MaxLine+1), MaxLine+1)
		for sc.Scan() {
			var ev Event
			if err := json.Unmarshal(sc.Bytes(), &ev); err != nil || ev.Seq <= last || ev.At.IsZero() || ev.Kind == "" || ev.ID == "" {
				j.st.BadLines++
				continue
			}
			last = ev.Seq
			ev.Open = false
			sg.note(ev, int64(len(sc.Bytes()))+1)
			j.events = append(j.events, ev)
		}
		bad := sc.Err() != nil
		fi, _ := f.Stat()
		clean = !bad && fi != nil && fi.Size() > 0 && endsWithNewline(f, fi.Size())
		f.Close()
		if bad {
			// A line longer than MaxLine was never written by this package:
			// what follows it in this file is not trusted.
			j.st.BadLines++
		}
		if sg.count == 0 {
			_ = os.Remove(filepath.Join(j.cfg.Dir, n))
			clean = false
			continue
		}
		if fi != nil {
			sg.size = fi.Size()
		}
		j.segs = append(j.segs, sg)
	}
	sort.SliceStable(j.events, func(a, b int) bool { return less(&j.events[a], &j.events[b]) })
	j.nextSeq = last + 1
	// The last segment takes further events when it is whole (it ends with
	// a complete line) and has room; otherwise the next event starts a new
	// one.
	if n := len(j.segs); n > 0 && clean && j.segs[n-1].count < j.segEv {
		if f, err := os.OpenFile(filepath.Join(j.cfg.Dir, j.segs[n-1].name), os.O_WRONLY|os.O_APPEND|oNoFollow, 0); err == nil {
			j.f = f
		}
	}
	return nil
}

func endsWithNewline(f *os.File, size int64) bool {
	var b [1]byte
	_, err := f.ReadAt(b[:], size-1)
	return err == nil && b[0] == '\n'
}

func (sg *segment) note(ev Event, n int64) {
	end := eventEnd(&ev)
	if sg.count == 0 {
		sg.first, sg.oldest, sg.newest = ev.Seq, end, end
	}
	sg.count++
	sg.last = ev.Seq
	sg.size += n
	if end.Before(sg.oldest) {
		sg.oldest = end
	}
	if end.After(sg.newest) {
		sg.newest = end
	}
}

func less(a, b *Event) bool {
	if !a.At.Equal(b.At) {
		return a.At.Before(b.At)
	}
	return a.Seq < b.Seq
}

func (j *Journal) sync(f *os.File) {
	if !j.cfg.noSync {
		_ = f.Sync()
	}
}

func (j *Journal) syncDir() {
	if j.cfg.noSync {
		return
	}
	if d, err := os.Open(j.cfg.Dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
}

func clipBytes(s string, max int) string {
	if len(s) <= max {
		return s
	}
	s = s[:max]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s + "…"
}

// encode renders ev as one line of at most MaxLine bytes: the texts are
// clipped first, then dropped if the line is still too long.
func encode(ev Event) ([]byte, Event) {
	ev.Open = false
	ev.Label = clipBytes(ev.Label, MaxLabel)
	ev.Evidence = clipBytes(ev.Evidence, MaxEvidence)
	ev.Reason = clipBytes(ev.Reason, 64)
	for i := 0; ; i++ {
		b, err := json.Marshal(ev)
		if err == nil && len(b)+1 <= MaxLine {
			return append(b, '\n'), ev
		}
		switch i {
		case 0:
			ev.Evidence = clipBytes(ev.Evidence, 120)
		case 1:
			ev.Evidence, ev.Label = "", clipBytes(ev.Label, 32)
		default:
			return nil, ev
		}
	}
}

// append writes ev (Seq assigned here) and applies the bounds. The caller
// holds j.mu.
func (j *Journal) append(ev Event) (Event, error) {
	ev.Seq = j.nextSeq
	line, ev := encode(ev)
	if line == nil {
		return ev, errors.New("event does not fit one line")
	}
	if j.f == nil || len(j.segs) == 0 || j.segs[len(j.segs)-1].count >= j.segEv {
		if err := j.rotate(ev.Seq); err != nil {
			return ev, err
		}
	}
	sg := j.segs[len(j.segs)-1]
	if _, err := j.f.Write(line); err != nil {
		// A partial line would make the rest of the segment unreadable: the
		// next event starts a new one.
		j.closeActive()
		return ev, err
	}
	if !j.cfg.noSync {
		_ = j.f.Sync()
	}
	j.nextSeq++
	sg.note(ev, int64(len(line)))
	j.insert(ev)
	j.st.Written++
	j.enforce()
	return ev, nil
}

func (j *Journal) insert(ev Event) {
	i := len(j.events)
	for i > 0 && less(&ev, &j.events[i-1]) {
		i--
	}
	j.events = append(j.events, Event{})
	copy(j.events[i+1:], j.events[i:])
	j.events[i] = ev
}

func (j *Journal) closeActive() {
	if j.f != nil {
		j.sync(j.f)
		_ = j.f.Close()
		j.f = nil
	}
}

func (j *Journal) rotate(first uint64) error {
	j.closeActive()
	name := segName(first)
	f, err := os.OpenFile(filepath.Join(j.cfg.Dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_APPEND|oNoFollow, 0o600)
	if err != nil {
		return err
	}
	j.f = f
	j.segs = append(j.segs, &segment{name: name, first: first})
	j.syncDir()
	return nil
}

func (j *Journal) totals() (n int, size int64) {
	for _, sg := range j.segs {
		n += sg.count
		size += sg.size
	}
	return n, size
}

// dropOldest removes the oldest segment file and its events.
func (j *Journal) dropOldest() {
	sg := j.segs[0]
	if len(j.segs) == 1 {
		j.closeActive()
	}
	_ = os.Remove(filepath.Join(j.cfg.Dir, sg.name))
	j.segs = j.segs[1:]
	keep := j.events[:0]
	for _, ev := range j.events {
		if ev.Seq < sg.first || ev.Seq > sg.last {
			keep = append(keep, ev)
		}
	}
	j.st.Trimmed += uint64(len(j.events) - len(keep))
	j.events = keep
}

// enforce applies the count, byte and segment bounds by dropping whole
// segments, oldest first.
func (j *Journal) enforce() {
	for len(j.segs) > 1 {
		n, size := j.totals()
		if n <= j.cfg.MaxEvents && size <= j.maxFill && len(j.segs) <= MaxSegments {
			break
		}
		j.dropOldest()
	}
}

// trimAge removes the events older than MaxAge: whole segments, and the
// expired head of the oldest remaining one (rewritten through a temporary
// file, at most once per TrimEvery unless force).
func (j *Journal) trimAge(now time.Time, force bool) {
	cut := now.Add(-j.cfg.MaxAge)
	for len(j.segs) > 0 && j.segs[0].newest.Before(cut) {
		j.dropOldest()
	}
	if len(j.segs) == 0 || !j.segs[0].oldest.Before(cut) {
		return
	}
	if !force && now.Sub(j.lastTrim) < TrimEvery && !now.Before(j.lastTrim) {
		return
	}
	j.lastTrim = now
	sg := j.segs[0]
	if len(j.segs) == 1 {
		// Never rewrite the file being appended to: close it, the next
		// event starts a new segment.
		j.closeActive()
	}
	var keep []Event
	for _, ev := range j.events {
		if ev.Seq >= sg.first && ev.Seq <= sg.last && !eventEnd(&ev).Before(cut) {
			keep = append(keep, ev)
		}
	}
	sort.Slice(keep, func(a, b int) bool { return keep[a].Seq < keep[b].Seq })
	if len(keep) == 0 {
		j.dropOldest()
		return
	}
	nsg := &segment{name: segName(keep[0].Seq)}
	var buf bytes.Buffer
	for _, ev := range keep {
		line, _ := encode(ev)
		if line == nil {
			continue
		}
		buf.Write(line)
		nsg.note(ev, int64(len(line)))
	}
	tmp := filepath.Join(j.cfg.Dir, nsg.name+tmpSuffix)
	if err := j.writeFile(tmp, buf.Bytes()); err != nil {
		_ = os.Remove(tmp)
		j.st.WriteErrors++
		return
	}
	// The kept events all have a sequence number above the segment's first
	// (its first event is expired), so the new name differs from the old.
	if err := os.Rename(tmp, filepath.Join(j.cfg.Dir, nsg.name)); err != nil {
		_ = os.Remove(tmp)
		j.st.WriteErrors++
		return
	}
	if nsg.name != sg.name {
		_ = os.Remove(filepath.Join(j.cfg.Dir, sg.name))
	}
	j.syncDir()
	kept := map[uint64]bool{}
	for _, ev := range keep {
		kept[ev.Seq] = true
	}
	out := j.events[:0]
	for _, ev := range j.events {
		if ev.Seq < sg.first || ev.Seq > sg.last || kept[ev.Seq] {
			out = append(out, ev)
		}
	}
	j.st.Trimmed += uint64(len(j.events) - len(out))
	j.events = out
	// The rewritten segment keeps the old one's sequence range, so a later
	// drop of it removes exactly its events.
	nsg.last = sg.last
	j.segs[0] = nsg
}

// eventEnd is the last moment an event speaks about.
func eventEnd(ev *Event) time.Time {
	if ev.LastAt != nil {
		return *ev.LastAt
	}
	return ev.At
}

func (j *Journal) writeFile(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|oNoFollow, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if !j.cfg.noSync {
		if err := f.Sync(); err != nil {
			f.Close()
			return err
		}
	}
	return f.Close()
}

// ------------------------------------------------------------ checkpoint ---

func (j *Journal) loadCheckpoint() {
	p := filepath.Join(j.cfg.Dir, checkpointFile)
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > MaxCheckpoint {
		return
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return
	}
	var cp checkpoint
	if json.Unmarshal(b, &cp) != nil || cp.Version != 1 || cp.LastPass.IsZero() {
		return
	}
	for _, o := range cp.Objects {
		if o == nil || o.Kind == "" || o.ID == "" || o.State == "" || o.LastSeen.IsZero() || len(j.objs) >= MaxObjects {
			continue
		}
		j.objs[objKey(o.Kind, o.ID)] = o
	}
	j.lastPass, j.cpDigest, j.st.ClearedAt, j.st.Restored = cp.LastPass, cp.Digest, cp.ClearedAt, true
	if cp.NextSeq > j.nextSeq {
		j.nextSeq = cp.NextSeq
	}
	// Events written after this checkpoint (a crash between the two
	// writes): the object's recorded state follows them, so the first pass
	// does not report the same change again.
	replay := make([]Event, 0, 8)
	for _, ev := range j.events {
		if ev.Seq > cp.Seq {
			replay = append(replay, ev)
		}
	}
	sort.Slice(replay, func(a, b int) bool { return replay[a].Seq < replay[b].Seq })
	for _, ev := range replay {
		o := j.objs[objKey(ev.Kind, ev.ID)]
		if o == nil || ev.Class == ClassCollector && ev.Kind != KindSource {
			continue
		}
		o.State, o.Since, o.Open, o.Flap = ev.To, eventEnd(&ev), ev.AfterGap != nil, nil
		if o.LastSeen.Before(o.Since) {
			o.LastSeen = o.Since
		}
	}
}

// writeCheckpoint replaces the checkpoint atomically. The caller holds j.mu.
func (j *Journal) writeCheckpoint(now time.Time) {
	cp := checkpoint{Version: 1, Digest: j.cfg.Digest, WrittenAt: now, LastPass: j.lastPass, NextSeq: j.nextSeq, ClearedAt: j.st.ClearedAt, Objects: make([]*object, 0, len(j.objs))}
	if j.nextSeq > 0 {
		cp.Seq = j.nextSeq - 1
	}
	for _, o := range j.objs {
		cp.Objects = append(cp.Objects, o)
	}
	sort.Slice(cp.Objects, func(a, b int) bool {
		return objKey(cp.Objects[a].Kind, cp.Objects[a].ID) < objKey(cp.Objects[b].Kind, cp.Objects[b].ID)
	})
	b, err := json.Marshal(cp)
	if err == nil && len(b) > MaxCheckpoint {
		// Too large with the texts: the states and times are what a restart
		// needs.
		slim := cp
		slim.Objects = make([]*object, len(cp.Objects))
		for i, o := range cp.Objects {
			c := *o
			c.Evidence, c.Label = "", ""
			if c.Flap != nil {
				f := *c.Flap
				f.Evidence, f.First.Evidence, f.First.Label = "", "", ""
				c.Flap = &f
			}
			slim.Objects[i] = &c
		}
		b, err = json.Marshal(slim)
	}
	if err == nil && len(b) > MaxCheckpoint {
		err = fmt.Errorf("checkpoint of %d bytes exceeds %d", len(b), MaxCheckpoint)
	}
	p := filepath.Join(j.cfg.Dir, checkpointFile)
	if err == nil {
		tmp := p + tmpSuffix
		if err = j.writeFile(tmp, b); err == nil {
			err = os.Rename(tmp, p)
		}
		if err != nil {
			_ = os.Remove(tmp)
		}
	}
	j.lastCP, j.dirty = now, false
	if err != nil {
		j.st.CheckpointError = clipBytes(err.Error(), 160)
		return
	}
	j.syncDir()
	j.st.CheckpointAt, j.st.CheckpointError = tp(now), ""
}

// ----------------------------------------------------------- observation ---

func secs(d time.Duration) *int64 {
	s := int64(d / time.Second)
	if s < 0 {
		s = 0
	}
	return &s
}

// emit writes one event inside the hourly write budget. The caller holds
// j.mu.
func (j *Journal) emit(now time.Time, ev Event) {
	cut := now.Add(-time.Hour).Unix()
	k := 0
	for _, w := range j.writes {
		if w > cut && w <= now.Unix() {
			j.writes[k] = w
			k++
		}
	}
	j.writes = j.writes[:k]
	if len(j.writes) >= j.cfg.WritesPerHour {
		j.st.DroppedBudget++
		return
	}
	if _, err := j.append(ev); err != nil {
		j.st.WriteErrors++
		return
	}
	j.writes = append(j.writes, now.Unix())
	j.dirty = true
}

// SetDigest tells the journal which compiled object list the collector
// runs with now, and which objects it names. Objects of another list that
// are no longer named are forgotten (without an event); a changed list is
// one event of class "collector".
func (j *Journal) SetDigest(digest string, known func(kind, id string) bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	now := j.now()
	j.cfg.Digest = digest
	if !j.st.Restored || j.cpDigest == digest {
		j.cpDigest = digest
		return
	}
	for k, o := range j.objs {
		if o.Class == ClassCollector {
			continue
		}
		if known == nil || !known(o.Kind, o.ID) {
			delete(j.objs, k)
		}
	}
	j.emit(now, Event{At: now, Class: ClassCollector, Kind: KindConfig, ID: CollectorID, Label: "采集范围", From: short(j.cpDigest), To: short(digest), Source: SourceCollector, Reason: ReasonConfig,
		Evidence: "网关安装了新的对象清单：被记录的链路、出口和目标随之更新；不再存在的对象不再跟踪，新增的对象从这次读取起建立基线"})
	j.cpDigest = digest
	j.dirty = true
}

func short(d string) string {
	if d == "" {
		return "-"
	}
	if len(d) > 12 {
		return d[:12]
	}
	return d
}

// Observe is one pass: the readings of this pass, taken at now. Objects
// without a reading keep their state; how long they have gone unread is
// what makes a gap.
func (j *Journal) Observe(at time.Time, obs []Observation) {
	now := trunc(at)
	j.mu.Lock()
	defer j.mu.Unlock()
	if !j.lastPass.IsZero() {
		d := now.Sub(j.lastPass)
		if d > j.cfg.GapAfter || d < 0 {
			reason, why := ReasonStall, "采集停顿"
			switch {
			case d < 0:
				reason, why = ReasonClock, "系统时钟被调回"
			case j.fresh:
				reason, why = ReasonRestart, "采集服务没有运行"
			}
			ev := Event{At: now, Class: ClassCollector, Kind: KindCollector, ID: CollectorID, Label: "链路日志采集", From: StateUnknown, To: StateCollecting,
				Source: SourceCollector, Reason: reason, AfterGap: &Gap{From: j.lastPass, To: now}}
			if d >= 0 {
				ev.PrevForS = secs(d)
				ev.Evidence = fmt.Sprintf("%s：%s 到 %s 之间（%d 秒）没有采集，这段时间里的状态未知、发生过的变化没有记录", why, stamp(j.lastPass), stamp(now), int64(d/time.Second))
			} else {
				ev.Evidence = fmt.Sprintf("%s：上一次采集记在 %s，晚于现在的 %s；之前的持续时间不再延续", why, stamp(j.lastPass), stamp(now))
			}
			j.emit(now, ev)
		}
	} else if !j.st.Restored && j.st.BaselineAt == nil {
		j.st.BaselineAt = tp(now)
		j.dirty = true
	}
	for i := range obs {
		j.observe(now, &obs[i])
	}
	j.closeFlaps(now)
	j.lastPass, j.fresh = now, false
	j.st.LastPass = tp(now)
	if j.dirty || now.Sub(j.lastCP) >= CheckpointEvery || now.Before(j.lastCP) {
		j.writeCheckpoint(now)
	}
	j.trimAge(now, false)
}

func stamp(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05Z") }

func (j *Journal) observe(now time.Time, o *Observation) {
	if o.State == "" || o.Kind == "" || o.ID == "" {
		return
	}
	key := objKey(o.Kind, o.ID)
	obj := j.objs[key]
	var srcAt *time.Time
	if !o.SourceAt.IsZero() {
		srcAt = tp(trunc(o.SourceAt))
	}
	if obj == nil {
		if len(j.objs) >= MaxObjects {
			j.st.ObjectsRefused++
			return
		}
		// Baseline: the state was already there; no event.
		j.objs[key] = &object{Class: o.Class, Kind: o.Kind, ID: o.ID, Label: clipBytes(o.Label, MaxLabel), Source: o.Source, State: o.State,
			Reason: o.Reason, Evidence: clipBytes(o.Evidence, MaxEvidence), Since: now, Open: true, LastSeen: now, SourceAt: srcAt}
		j.dirty = true
		return
	}
	d := now.Sub(obj.LastSeen)
	gap := d > j.cfg.GapAfter || d < 0
	ev := Event{At: now, Class: o.Class, Kind: o.Kind, ID: o.ID, Label: o.Label, From: obj.State, To: o.State, Source: o.Source, Reason: o.Reason, Evidence: o.Evidence, SourceAt: srcAt}
	switch {
	case o.State == obj.State:
		if gap {
			// Unchanged across a gap: it may have changed and changed back
			// in between, so its duration starts again.
			obj.Since, obj.Open = now, true
			j.dirty = true
		}
	case gap:
		ev.AfterGap = &Gap{From: obj.LastSeen, To: now}
		if obj.LastSeen.After(obj.Since) {
			ev.PrevForS = secs(obj.LastSeen.Sub(obj.Since))
		}
		ev.PrevOpen = true
		j.transition(obj, now, ev, true)
	default:
		ev.PrevForS, ev.PrevOpen = secs(now.Sub(obj.Since)), obj.Open
		j.transition(obj, now, ev, false)
	}
	obj.Class, obj.Label, obj.Source = o.Class, clipBytes(o.Label, MaxLabel), o.Source
	obj.LastSeen, obj.Reason, obj.Evidence, obj.SourceAt = now, o.Reason, clipBytes(o.Evidence, MaxEvidence), srcAt
}

// transition records one change of obj: a single event, or one more change
// of its merged record.
func (j *Journal) transition(obj *object, now time.Time, ev Event, afterGap bool) {
	switch {
	case obj.Flap != nil:
		f := obj.Flap
		// One more change of an open merged record: it reaches the
		// checkpoint with the next regular write (CheckpointEvery), not with
		// a write of its own per change.
		f.Changes++
		f.LastAt, f.To, f.Reason, f.Evidence = now, ev.To, ev.Reason, clipBytes(ev.Evidence, MaxEvidence)
		j.st.Merged++
	default:
		cut := now.Add(-j.cfg.FlapWindow).Unix()
		k := 0
		for _, r := range obj.Recent {
			if r > cut && r <= now.Unix() {
				obj.Recent[k] = r
				k++
			}
		}
		obj.Recent = obj.Recent[:k]
		if len(obj.Recent) >= j.cfg.FlapAfter {
			_, first := encode(ev)
			obj.Flap = &flap{FirstAt: now, LastAt: now, Changes: 1, From: ev.From, To: ev.To, Reason: ev.Reason, Evidence: clipBytes(ev.Evidence, MaxEvidence), First: first}
			j.st.Merged++
			j.dirty = true
		} else {
			j.emit(now, ev)
			obj.Recent = append(obj.Recent, now.Unix())
		}
	}
	obj.State, obj.Since, obj.Open = ev.To, now, afterGap
}

// flapEvent is the merged record of f as an event.
func flapEvent(obj *object, f *flap) Event {
	if f.Changes <= 1 {
		return f.First
	}
	ev := Event{At: f.FirstAt, LastAt: tp(f.LastAt), Changes: f.Changes, Class: obj.Class, Kind: obj.Kind, ID: obj.ID, Label: obj.Label, From: f.From, To: f.To,
		Source: obj.Source, Reason: f.Reason}
	ev.Evidence = fmt.Sprintf("抖动合并：%s 到 %s 之间变化了 %d 次（是多次变化，不是一次连续的中断）；合并前是 %s，最后一次变化之后是 %s", stamp(f.FirstAt), stamp(f.LastAt), f.Changes, f.From, f.To)
	if f.Evidence != "" {
		ev.Evidence += "。最后一次的依据：" + f.Evidence
	}
	return ev
}

// closeFlaps writes the merged records whose object has been quiet for
// FlapQuiet, and the ones that have been counting for FlapMax.
func (j *Journal) closeFlaps(now time.Time) {
	for _, obj := range j.objs {
		f := obj.Flap
		if f == nil {
			continue
		}
		quiet := now.Sub(f.LastAt) >= j.cfg.FlapQuiet
		long := now.Sub(f.FirstAt) >= j.cfg.FlapMax
		if !quiet && !long && !now.Before(f.FirstAt) {
			continue
		}
		j.emit(now, flapEvent(obj, f))
		obj.Flap = nil
		obj.Recent = obj.Recent[:0]
		if long && !quiet {
			// Still changing: the next change opens a new merged record
			// instead of single events.
			for i := 0; i < j.cfg.FlapAfter; i++ {
				obj.Recent = append(obj.Recent, now.Unix())
			}
		}
		j.dirty = true
	}
}

// Close writes the checkpoint and closes the files. Open merged records
// stay open in the checkpoint.
func (j *Journal) Close() {
	if j == nil {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if !j.lastPass.IsZero() {
		j.writeCheckpoint(j.now())
	}
	j.closeActive()
}

// Clear removes every event, the tracked states and the checkpoint. The
// next pass is a baseline.
func (j *Journal) Clear() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	n := len(j.events)
	j.closeActive()
	for _, sg := range j.segs {
		_ = os.Remove(filepath.Join(j.cfg.Dir, sg.name))
	}
	_ = os.Remove(filepath.Join(j.cfg.Dir, checkpointFile))
	_ = os.Remove(filepath.Join(j.cfg.Dir, checkpointFile+tmpSuffix))
	j.syncDir()
	j.events, j.segs, j.objs, j.writes = nil, nil, map[string]*object{}, nil
	j.lastPass, j.fresh, j.dirty = time.Time{}, true, false
	now := j.now()
	j.st.ClearedAt, j.st.BaselineAt, j.st.Restored, j.st.LastPass, j.st.CheckpointAt = tp(now), nil, false, nil, nil
	j.cpDigest = j.cfg.Digest
	return n
}

// diskBytes sums the regular files in the directory.
func diskBytes(dir string) int64 {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	var n int64
	for _, e := range ents {
		if fi, err := os.Lstat(filepath.Join(dir, e.Name())); err == nil && fi.Mode().IsRegular() {
			n += fi.Size()
		}
	}
	return n
}

// Stats describes the journal now.
func (j *Journal) Stats() Stats {
	j.mu.Lock()
	defer j.mu.Unlock()
	st := j.st
	st.Events, st.Bytes = j.totals()
	st.Segments, st.Objects = len(j.segs), len(j.objs)
	if len(j.events) > 0 {
		st.Oldest, st.Newest = tp(j.events[0].At), tp(j.events[len(j.events)-1].At)
	}
	for _, o := range j.objs {
		if o.Flap != nil {
			st.OpenFlaps++
		}
	}
	st.DiskBytes = diskBytes(j.cfg.Dir)
	st.MaxEvents, st.MaxAgeS, st.Budget = j.cfg.MaxEvents, int64(j.cfg.MaxAge/time.Second), j.budget
	st.GapAfterS, st.FlapAfter, st.FlapWinS, st.FlapQuietS, st.WritesHour = int64(j.cfg.GapAfter/time.Second), j.cfg.FlapAfter,
		int64(j.cfg.FlapWindow/time.Second), int64(j.cfg.FlapQuiet/time.Second), j.cfg.WritesPerHour
	return st
}

// ----------------------------------------------------------------- query ---

// TokenRe is the shape of a class, kind or object id in a query.
var TokenRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,95}$`)

var cursorRe = regexp.MustCompile(`^([0-9]{1,12})-([0-9]{1,19})$`)

// Query selects events, newest first. Every field is optional.
type Query struct {
	Class string `json:"class,omitempty"`
	Kind  string `json:"kind,omitempty"`
	// ID is the object id (with Kind: one object).
	ID string `json:"id,omitempty"`
	// From / To: RFC 3339 times, inclusive.
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
	// Before is the NextBefore of the previous page.
	Before string `json:"before,omitempty"`
	Limit  int    `json:"limit,omitempty"`
}

type parsedQuery struct {
	q        Query
	from, to time.Time
	hasFrom  bool
	hasTo    bool
	curAt    int64
	curSeq   uint64
	hasCur   bool
	limit    int
}

// Validate checks every field.
func (q Query) Validate() error {
	_, err := q.parse()
	return err
}

func (q Query) parse() (parsedQuery, error) {
	p := parsedQuery{q: q, limit: q.Limit}
	for name, v := range map[string]string{"class": q.Class, "kind": q.Kind, "id": q.ID} {
		if v != "" && !TokenRe.MatchString(v) {
			return p, fmt.Errorf("%s: not a name", name)
		}
	}
	var err error
	if q.From != "" {
		if p.from, err = time.Parse(time.RFC3339, q.From); err != nil {
			return p, errors.New("from: an RFC 3339 time")
		}
		p.hasFrom = true
	}
	if q.To != "" {
		if p.to, err = time.Parse(time.RFC3339, q.To); err != nil {
			return p, errors.New("to: an RFC 3339 time")
		}
		p.hasTo = true
	}
	if p.hasFrom && p.hasTo && p.to.Before(p.from) {
		return p, errors.New("to is before from")
	}
	if q.Before != "" {
		m := cursorRe.FindStringSubmatch(q.Before)
		if m == nil {
			return p, errors.New("before: not a page cursor")
		}
		p.curAt, _ = strconv.ParseInt(m[1], 10, 64)
		p.curSeq, _ = strconv.ParseUint(m[2], 10, 64)
		p.hasCur = true
	}
	switch {
	case q.Limit < 0 || q.Limit > PageMax:
		return p, fmt.Errorf("limit: 1 to %d", PageMax)
	case q.Limit == 0:
		p.limit = PageDefault
	}
	return p, nil
}

// Values renders q as query parameters (the collector's status socket).
func (q Query) Values() url.Values {
	v := url.Values{}
	for k, s := range map[string]string{"class": q.Class, "kind": q.Kind, "id": q.ID, "from": q.From, "to": q.To, "before": q.Before} {
		if s != "" {
			v.Set(k, s)
		}
	}
	if q.Limit > 0 {
		v.Set("limit", strconv.Itoa(q.Limit))
	}
	return v
}

// QueryFrom reads a Query from query parameters: only the known names, one
// value each.
func QueryFrom(v url.Values) (Query, error) {
	var q Query
	for k, vs := range v {
		if len(vs) != 1 {
			return q, fmt.Errorf("%s: one value", k)
		}
		s := vs[0]
		switch k {
		case "class":
			q.Class = s
		case "kind":
			q.Kind = s
		case "id":
			q.ID = s
		case "from":
			q.From = s
		case "to":
			q.To = s
		case "before":
			q.Before = s
		case "limit":
			n, err := strconv.Atoi(s)
			if err != nil || n < 1 {
				return q, fmt.Errorf("limit: 1 to %d", PageMax)
			}
			q.Limit = n
		default:
			return q, fmt.Errorf("unknown parameter %q", k)
		}
	}
	return q, q.Validate()
}

func (p *parsedQuery) match(ev *Event) bool {
	q := &p.q
	if q.Class != "" && ev.Class != q.Class || q.Kind != "" && ev.Kind != q.Kind || q.ID != "" && ev.ID != q.ID {
		return false
	}
	// A merged record speaks about [At, LastAt]: it matches a range it
	// overlaps.
	if p.hasFrom && eventEnd(ev).Before(p.from) || p.hasTo && ev.At.After(p.to) {
		return false
	}
	return true
}

// Page is one page of events, newest first.
type Page struct {
	Events []Event `json:"events"`
	// NextBefore: pass it as Before for the next (older) page; "" when
	// there is none.
	NextBefore string `json:"next_before,omitempty"`
	// OpenMerged counts the merged records still being counted that are in
	// Events (first page only; they have no Seq yet).
	OpenMerged int   `json:"open_merged,omitempty"`
	Stats      Stats `json:"stats"`
}

// Query returns one page. Events older than MaxAge are never returned,
// whether or not they have been removed from disk yet.
func (j *Journal) Query(q Query) (Page, error) {
	p, err := q.parse()
	if err != nil {
		return Page{}, err
	}
	page := Page{Events: []Event{}, Stats: j.Stats()}
	j.mu.Lock()
	defer j.mu.Unlock()
	now := j.now()
	cut := now.Add(-j.cfg.MaxAge)
	if !p.hasCur {
		var open []Event
		for _, obj := range j.objs {
			if obj.Flap == nil {
				continue
			}
			ev := flapEvent(obj, obj.Flap)
			ev.Open, ev.Seq = true, 0
			if p.match(&ev) {
				open = append(open, ev)
			}
		}
		sort.Slice(open, func(a, b int) bool {
			if !open[a].At.Equal(open[b].At) {
				return open[a].At.After(open[b].At)
			}
			return objKey(open[a].Kind, open[a].ID) < objKey(open[b].Kind, open[b].ID)
		})
		page.Events, page.OpenMerged = append(page.Events, open...), len(open)
	}
	n := 0
	for i := len(j.events) - 1; i >= 0; i-- {
		ev := &j.events[i]
		if eventEnd(ev).Before(cut) {
			continue
		}
		if p.hasCur && (ev.At.Unix() > p.curAt || ev.At.Unix() == p.curAt && ev.Seq >= p.curSeq) {
			continue
		}
		if !p.match(ev) {
			continue
		}
		if n == p.limit {
			last := page.Events[len(page.Events)-1]
			page.NextBefore = fmt.Sprintf("%d-%d", last.At.Unix(), last.Seq)
			break
		}
		page.Events = append(page.Events, *ev)
		n++
	}
	return page, nil
}

// --------------------------------------------------------------- current ---

// Flapping describes an open merged record of an object.
type Flapping struct {
	Changes int       `json:"changes"`
	FirstAt time.Time `json:"first_at"`
	LastAt  time.Time `json:"last_at"`
}

// CurrentObject is one object's state now.
type CurrentObject struct {
	Class  string `json:"class"`
	Kind   string `json:"kind"`
	ID     string `json:"id"`
	Label  string `json:"label,omitempty"`
	Source string `json:"source,omitempty"`
	// State is the last state read. Stale: it has not been read for longer
	// than the gap threshold, so the state now is unknown.
	State string `json:"state"`
	Stale bool   `json:"stale,omitempty"`
	// Level: ok | abnormal | info (sources.go Level).
	Level    string `json:"level"`
	Reason   string `json:"reason,omitempty"`
	Evidence string `json:"evidence,omitempty"`
	// Since / ForS: how long State has been observed without a break.
	// SinceOpen: it began earlier (it was there at the first reading, or a
	// gap precedes it), so ForS is a lower bound.
	Since     time.Time  `json:"since"`
	ForS      int64      `json:"for_s"`
	SinceOpen bool       `json:"since_open,omitempty"`
	LastSeen  time.Time  `json:"last_seen"`
	SourceAt  *time.Time `json:"source_at,omitempty"`
	Flapping  *Flapping  `json:"flapping,omitempty"`
}

// Current is every tracked object's state now.
type Current struct {
	At      time.Time       `json:"at"`
	Objects []CurrentObject `json:"objects"`
	// LastPass: the collector's last pass (nil: none yet).
	LastPass *time.Time `json:"last_pass,omitempty"`
}

var classOrder = map[string]int{ClassPath: 0, ClassRelay: 1, ClassTunnel: 2, ClassWSS: 3, ClassExternalExit: 4, ClassSniffTarget: 5, ClassCollector: 6}

// Current lists the tracked objects (the collection gap object, which has
// no state of its own, is not one of them).
func (j *Journal) Current() Current {
	j.mu.Lock()
	defer j.mu.Unlock()
	now := j.now()
	c := Current{At: now, Objects: make([]CurrentObject, 0, len(j.objs))}
	if !j.lastPass.IsZero() {
		c.LastPass = tp(j.lastPass)
	}
	for _, o := range j.objs {
		co := CurrentObject{Class: o.Class, Kind: o.Kind, ID: o.ID, Label: o.Label, Source: o.Source, State: o.State, Level: Level(o.Kind, o.State), Reason: o.Reason, Evidence: o.Evidence,
			Since: o.Since, SinceOpen: o.Open, LastSeen: o.LastSeen, SourceAt: o.SourceAt}
		if d := o.LastSeen.Sub(o.Since); d > 0 {
			co.ForS = int64(d / time.Second)
		}
		if d := now.Sub(o.LastSeen); d > j.cfg.GapAfter || d < 0 {
			co.Stale = true
		} else if d := now.Sub(o.Since); d > 0 {
			co.ForS = int64(d / time.Second)
		}
		if f := o.Flap; f != nil {
			co.Flapping = &Flapping{Changes: f.Changes, FirstAt: f.FirstAt, LastAt: f.LastAt}
		}
		c.Objects = append(c.Objects, co)
	}
	sort.Slice(c.Objects, func(a, b int) bool {
		x, y := &c.Objects[a], &c.Objects[b]
		if classOrder[x.Class] != classOrder[y.Class] {
			return classOrder[x.Class] < classOrder[y.Class]
		}
		if x.Kind != y.Kind {
			return x.Kind < y.Kind
		}
		return x.ID < y.ID
	})
	return c
}
