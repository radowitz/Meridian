package dnsjournal

// "meridian dns-journal": the reader process (Unit, rendered by
// compile.RenderDNSJournalUnit). It prepares the audit sink, follows the
// audit file once a second, keeps the journal and answers fixed requests on
// a status socket that answers uid 0 only (the host agent):
//
//	GET  /v1/health           Health
//	GET  /v1/journal          one Page (Query as query parameters)
//	GET  /v1/journal/summary  Summary (from, to)
//	POST /v1/journal/clear    no parameters: every record, the rotated audit
//	                          copies and the content of the audit file. The
//	                          answer (ClearResult) says whether all of it
//	                          went ("complete"), and if not what is left
//	                          and why, in counts and fixed words
//
// Its log lines carry counts and fixed texts only: never a name, an address
// or a line of the audit file.

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/radowitz/meridian/internal/sniff"
)

// DaemonConfig is the reader's command line.
type DaemonConfig struct {
	RawDir       string
	JournalDir   string
	StatusSocket string
	NeighIfaces  []string
	MaxRecords   int
	MaxAge       time.Duration
	MaxBytes     int64
	Poll         time.Duration
	// PrepareOnly: prepare the audit sink and exit (the unit's ExecStartPre).
	PrepareOnly bool
	// Fault: tests only, never a flag (the file-system calls of a clear).
	Fault Fault
}

func cleanAbs(name, p string) error {
	if p == "" || !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return fmt.Errorf("%s: a clean absolute path", name)
	}
	return nil
}

// ParseArgs parses the reader's flags.
func ParseArgs(args []string) (DaemonConfig, error) {
	var c DaemonConfig
	var neigh string
	fs := flag.NewFlagSet("dns-journal", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&c.RawDir, "raw-dir", RawDir, "directory of the resolver's audit file")
	fs.StringVar(&c.JournalDir, "journal-dir", JournalDir, "directory of the structured journal")
	fs.StringVar(&c.StatusSocket, "status-socket", "", "status socket (answers uid 0 only)")
	fs.StringVar(&neigh, "neigh-if", "", "LAN interfaces whose neighbour entries give a client's MAC (comma separated)")
	fs.IntVar(&c.MaxRecords, "max-records", DefaultMaxRecords, "records kept")
	fs.DurationVar(&c.MaxAge, "max-age", DefaultMaxAge, "age kept (the records, and the audit file and its rotated copies)")
	fs.Int64Var(&c.MaxBytes, "max-bytes", DefaultMaxBytes, "bytes for the audit file, its rotated copies, the queue and the journal together")
	fs.DurationVar(&c.Poll, "poll", time.Second, "how often the audit file is read")
	fs.BoolVar(&c.PrepareOnly, "prepare", false, "prepare the audit directory and file, then exit")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	if fs.NArg() > 0 {
		return c, errors.New("unexpected arguments")
	}
	for _, p := range strings.Split(neigh, ",") {
		if p = strings.TrimSpace(p); p != "" {
			c.NeighIfaces = append(c.NeighIfaces, p)
		}
	}
	if err := cleanAbs("raw-dir", c.RawDir); err != nil {
		return c, err
	}
	if err := cleanAbs("journal-dir", c.JournalDir); err != nil {
		return c, err
	}
	if c.StatusSocket != "" {
		if err := cleanAbs("status-socket", c.StatusSocket); err != nil {
			return c, err
		}
	}
	switch {
	case c.RawDir == c.JournalDir || strings.HasPrefix(c.JournalDir, c.RawDir+"/"):
		return c, errors.New("journal-dir must not be the raw directory or inside it (the raw directory is mounted into the resolver)")
	case c.MaxRecords <= 0 || c.MaxAge < time.Minute || c.MaxBytes < 1<<20:
		return c, errors.New("max-records > 0, max-age >= 1m, max-bytes >= 1 MiB")
	case c.Poll < 100*time.Millisecond || c.Poll > time.Minute:
		return c, errors.New("poll: 100ms..1m")
	}
	return c, nil
}

// Health is the reader's state.
type Health struct {
	Ready     bool      `json:"ready"`
	StartedAt time.Time `json:"started_at"`
	MACLookup bool      `json:"mac_lookup"`
	// Journal is nil when the journal could not be opened (the reader then
	// only keeps the raw directory inside its budget).
	Journal *Stats    `json:"journal,omitempty"`
	Reader  TailStats `json:"reader"`
	// NoJournalDropped counts the lines read while there was no journal.
	NoJournalDropped uint64 `json:"no_journal_dropped,omitempty"`
}

// Daemon is the reader: a Tailer feeding a Journal.
type Daemon struct {
	Journal   *Journal
	Tail      *Tailer
	MACLookup bool
	started   time.Time
	mu        sync.Mutex
	noJournal uint64
	// stepMu serialises a round of reading (Step) and a clear: no line is
	// read, and no record handed to the journal, between the clear of the
	// raw side and the clear of the journal, and two clears never interleave.
	stepMu     sync.Mutex
	journalDir string
	fault      Fault
}

// NewDaemon opens the journal and builds the reader for cfg; lookup is the
// MAC lookup (nil: none). A journal that cannot be opened is not fatal.
func NewDaemon(cfg DaemonConfig, lookup func(netip.Addr) string, now func() time.Time) (*Daemon, error) {
	b := SplitBudget(cfg.MaxBytes, Queue)
	d := &Daemon{MACLookup: lookup != nil, started: time.Now(), journalDir: cfg.JournalDir, fault: cfg.Fault}
	if now != nil {
		d.started = now()
	}
	j, err := Open(Config{Dir: cfg.JournalDir, MaxRecords: cfg.MaxRecords, MaxAge: cfg.MaxAge, MaxBytes: b.Journal, Now: now, Fault: cfg.Fault})
	if err == nil {
		j.Budget = &b
		d.Journal = j
	}
	d.Tail = NewTailer(TailConfig{Dir: cfg.RawDir, PositionPath: filepath.Join(cfg.JournalDir, positionFile), MaxRawBytes: b.Raw, MaxAge: cfg.MaxAge, Lookup: lookup, Now: now, Fault: cfg.Fault,
		Emit: func(r Record) {
			if d.Journal == nil {
				d.mu.Lock()
				d.noJournal++
				d.mu.Unlock()
				return
			}
			d.Journal.Add(r)
		}})
	return d, err
}

// Health describes the reader now.
func (d *Daemon) Health() Health {
	h := Health{StartedAt: d.started, MACLookup: d.MACLookup, Reader: d.Tail.Stats()}
	if d.Journal != nil {
		st := d.Journal.Stats()
		h.Journal = &st
	}
	d.mu.Lock()
	h.NoJournalDropped = d.noJournal
	d.mu.Unlock()
	h.Ready = h.Journal != nil && h.Reader.Following
	return h
}

// Step does one round of reading and housekeeping (Tailer.Step), never in
// the middle of a clear.
func (d *Daemon) Step() {
	d.stepMu.Lock()
	defer d.stepMu.Unlock()
	d.Tail.Step()
}

// ClearResidual is what a clear left behind.
type ClearResidual struct {
	// Segments / Records / Bytes: segment files of the structured journal
	// that could not be deleted (they still answer queries).
	Segments int   `json:"segments"`
	Records  int   `json:"records"`
	Bytes    int64 `json:"bytes"`
	// RawFiles / RawBytes: in the raw directory — rotated copies that could
	// not be deleted, the audit file when it could not be emptied.
	RawFiles int   `json:"raw_files"`
	RawBytes int64 `json:"raw_bytes"`
	// Unknown: a directory or a file could not be looked at, so more may
	// be left than is counted here.
	Unknown bool `json:"unknown,omitempty"`
}

// ClearResult is the answer of a clear: the reader's (Daemon.Clear) and the
// host agent's own (PurgeData).
type ClearResult struct {
	// Complete: everything a clear removes is gone. false: Residual says
	// what is left and Errors why; the same clear can be asked again.
	Complete bool `json:"complete"`
	// Cleared: records deleted; RawBytes: bytes removed from the raw
	// directory.
	Cleared  int   `json:"cleared"`
	RawBytes int64 `json:"raw_bytes"`
	// PurgedFiles / PurgedBytes: files deleted directly from the two
	// directories (PurgeData, or a reader without a journal).
	PurgedFiles int            `json:"purged_files,omitempty"`
	PurgedBytes int64          `json:"purged_bytes,omitempty"`
	Residual    *ClearResidual `json:"residual,omitempty"`
	Errors      []ClearError   `json:"errors,omitempty"`
	Stats       *Stats         `json:"stats,omitempty"`
}

func (r *ClearResult) left() *ClearResidual {
	if r.Residual == nil {
		r.Residual = &ClearResidual{}
	}
	return r.Residual
}

var (
	clearPartText  = map[string]string{PartJournal: "结构化日志", PartRaw: "审计目录"}
	clearCauseText = map[string]string{"permission": "权限不足", "read_only": "文件系统只读", "busy": "文件被占用", "no_space": "空间或配额不足", "io": "磁盘读写错误"}
)

// Text is the error in the panel's words (counts and fixed words only).
func (e ClearError) Text() string {
	part, cause := clearPartText[e.Part], clearCauseText[e.Cause]
	if part == "" {
		part = "解析日志"
	}
	if cause == "" {
		cause = "文件系统错误"
	}
	var what string
	switch e.Op {
	case "readdir":
		what = "目录读取失败"
	case "lstat":
		what = fmt.Sprintf("%d 个文件的状态读取失败", e.Count)
	case "truncate":
		what = "审计文件截断失败"
	case "write":
		what = "清除标记写入失败"
	default:
		what = fmt.Sprintf("%d 个文件删除失败", e.Count)
	}
	return part + what + "（" + cause + "）"
}

// Problem says what an incomplete clear left and why, in one line ("" when
// it is complete): counts and fixed words, never a path or a name.
func (r ClearResult) Problem() string {
	if r.Complete {
		return ""
	}
	var parts []string
	if x := r.Residual; x != nil {
		if x.Segments > 0 || x.Records > 0 || x.Bytes > 0 {
			parts = append(parts, fmt.Sprintf("结构化日志还留着 %d 个分段（%d 条记录，%d 字节）", x.Segments, x.Records, x.Bytes))
		}
		if x.RawFiles > 0 || x.RawBytes > 0 {
			parts = append(parts, fmt.Sprintf("审计目录还留着 %d 个文件（%d 字节）", x.RawFiles, x.RawBytes))
		}
		if x.Unknown {
			parts = append(parts, "有目录或文件读不到，留下的可能比数到的多")
		}
	}
	for _, e := range r.Errors {
		parts = append(parts, e.Text())
	}
	if len(parts) == 0 {
		return "没有确认全部清除"
	}
	return strings.Join(parts, "；")
}

// Clear removes every record, the rotated audit copies and the content of
// the audit file, and reports what it could not remove. No round of
// reading runs inside it (stepMu), and the journal discards what was still
// queued: nothing read before the clear is written after it.
func (d *Daemon) Clear() ClearResult {
	d.stepMu.Lock()
	defer d.stepMu.Unlock()
	var res ClearResult
	var errs clearErrs
	raw := d.Tail.Clear()
	res.RawBytes = raw.Freed
	errs = append(errs, raw.Errors...)
	if raw.Files > 0 || raw.Bytes > 0 || raw.Unknown {
		r := res.left()
		r.RawFiles, r.RawBytes, r.Unknown = raw.Files, raw.Bytes, raw.Unknown
	}
	if d.Journal != nil {
		rep := d.Journal.Clear()
		res.Cleared = rep.Cleared
		errs = append(errs, rep.Errors...)
		if x := rep.Residual; x != nil {
			r := res.left()
			r.Segments, r.Records, r.Bytes = x.Segments, x.Records, x.Bytes
		}
		if rep.Unknown {
			res.left().Unknown = true
		}
		st := d.Journal.Stats()
		res.Stats = &st
	} else {
		// No journal is open (its directory could not be used at start):
		// the segment files that are there go all the same.
		purgeSegments(d.journalDir, d.fault, &errs, &res)
	}
	res.Errors = errs.list()
	res.Complete = len(res.Errors) == 0 && res.Residual == nil
	return res
}

// Close stops the reader and the journal.
func (d *Daemon) Close() {
	d.Tail.Close()
	d.Journal.Close()
}

// StatusHandler serves the fixed requests. Every answer stays below
// sniff.MaxStatusAnswer (a page holds at most PageMax lines of at most
// MaxLine bytes; a summary at most SummaryDevices devices).
func (d *Daemon) StatusHandler() http.Handler {
	mux := http.NewServeMux()
	write := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	only := func(w http.ResponseWriter, r *http.Request, method string) bool {
		if r.Method != method {
			http.Error(w, method+" only", http.StatusMethodNotAllowed)
			return false
		}
		return true
	}
	noJournal := func(w http.ResponseWriter) bool {
		if d.Journal == nil {
			http.Error(w, "no journal", http.StatusNotFound)
			return true
		}
		return false
	}
	mux.HandleFunc("/v1/health", func(w http.ResponseWriter, r *http.Request) {
		if only(w, r, http.MethodGet) {
			write(w, d.Health())
		}
	})
	mux.HandleFunc("/v1/journal", func(w http.ResponseWriter, r *http.Request) {
		if !only(w, r, http.MethodGet) || noJournal(w) {
			return
		}
		q, err := QueryFrom(r.URL.Query())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		page, err := d.Journal.Query(q)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		write(w, page)
	})
	mux.HandleFunc("/v1/journal/summary", func(w http.ResponseWriter, r *http.Request) {
		if !only(w, r, http.MethodGet) || noJournal(w) {
			return
		}
		q, err := SummaryQueryFrom(r.URL.Query())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		sum, err := d.Journal.Summary(q)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		write(w, sum)
	})
	mux.HandleFunc("/v1/journal/clear", func(w http.ResponseWriter, r *http.Request) {
		if !only(w, r, http.MethodPost) {
			return
		}
		if r.ContentLength > 0 || r.URL.RawQuery != "" {
			http.Error(w, "no parameters", http.StatusBadRequest)
			return
		}
		write(w, d.Clear())
	})
	return mux
}

// Main runs "meridian dns-journal" until SIGTERM / SIGINT. Exit 2 usage,
// 1 failure to start.
func Main(args []string) int {
	cfg, err := ParseArgs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "meridian dns-journal:", err)
		return 2
	}
	// The sink first, whatever else fails: the resolver must find a regular
	// file in an existing directory.
	if err := PrepareSink(cfg.RawDir); err != nil {
		fmt.Fprintln(os.Stderr, "meridian-dns-journal-failed: audit sink:", err)
		return 1
	}
	if cfg.PrepareOnly {
		return 0
	}
	var lookup func(netip.Addr) string
	if len(cfg.NeighIfaces) > 0 {
		nt, err := sniff.NewNeighborTable(cfg.NeighIfaces)
		if err != nil {
			log.Printf("meridian-dns-journal: warning: neighbour table not available (%v): records carry no MAC", err)
		} else {
			lookup = nt.Lookup
		}
	}
	d, err := NewDaemon(cfg, lookup, nil)
	if err != nil {
		log.Printf("meridian-dns-journal: warning: journal not available (%v): lines are read and dropped, the raw directory is kept inside its budget", err)
	}
	defer d.Close()
	if cfg.StatusSocket != "" {
		sl, err := sniff.ListenStatus(cfg.StatusSocket, sniff.StatusRootOnly)
		if err != nil {
			fmt.Fprintln(os.Stderr, "meridian-dns-journal-failed: status socket:", err)
			return 1
		}
		go func() { _ = (&http.Server{Handler: d.StatusHandler(), ReadHeaderTimeout: 5 * time.Second}).Serve(sl) }()
	}
	b := SplitBudget(cfg.MaxBytes, Queue)
	log.Printf("%s: raw %s (at most %d bytes), journal %s (at most %d bytes, %d records, %s), queue %d, MAC lookup %v",
		ReadyMarker, cfg.RawDir, b.Raw, cfg.JournalDir, b.Journal, cfg.MaxRecords, cfg.MaxAge, Queue, lookup != nil)
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	tick := time.NewTicker(cfg.Poll)
	defer tick.Stop()
	d.Step()
	for {
		select {
		case <-tick.C:
			d.Step()
		case <-sig:
			return 0
		}
	}
}
