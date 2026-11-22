package hostexec

// Automatic SmartDNS re-read after a list update (docs/architecture.md
// 「名单与 SmartDNS 自动读入」).
//
// SmartDNS reads its domain-set files (geosite/*.txt, geosite/ordered/*.txt,
// keywords/*.txt under /var/lib/meridian) only at start; it has no reload
// for them. A list update that publishes files therefore asks for one
// restart of the gateway's resolver, a fixed action with no parameter:
//
//   - Change test: a sha256 over those files' names and contents. When it
//     equals the digest SmartDNS loaded, nothing runs (a geosite rewrite
//     with the same content is not a change).
//   - Loaded digest: every managed SmartDNS (re)start in the agent (this
//     re-read and the install restart in activate; rollback, withdraw and
//     restore reach SmartDNS only through activate) takes the digest under
//     the action lock right before the restart (publication also holds
//     that lock, so the files cannot change in between) and records it
//     only after the restart succeeded and 127.0.0.1:53 answered. No
//     resolver, a failed restart or no answer leave it unchanged. The
//     re-read reads the baseline only once it holds the lock.
//   - Baseline before the first managed restart: the files found at agent
//     start, when SmartDNS demonstrably started after their last change
//     and before the agent looked (systemd ActiveEnterTimestamp or the
//     container's StartedAt); else the digest the previous agent recorded.
//     Undeterminable: one conservative restart, whose digest then counts.
//   - meridian-dns-split: a chnroute change records split (and its reason)
//     in the pending record; when the restart runs and the config in force
//     uses meridian-dns-split, it is restarted first, regardless of the
//     digest. Its failure is recorded (split_error, result failed) but
//     SmartDNS is still restarted; its answer still advances the digest.
//     A pending record of an older agent (no cause) restarts SmartDNS
//     once and dns-split only if the config uses it.
//   - Coalescing: the first request schedules the restart DNSReloadWindow
//     (10s) later; publications until then join it.
//   - Rate limit: at most one restart per DNSReloadMinGap (5m), counted from
//     the previous attempt's start. A request inside the gap is never
//     dropped: it schedules one deferred restart at the end of the gap.
//   - The restart takes the action lock (never during install/rollback),
//     then smartdns.service or the meridian-smartdns container (whichever
//     runs), and polls 127.0.0.1:53 until it answers. The outcome, with the
//     restart and first-answer durations, is kept in
//     lists/smartdns-reload.json and returned by /v1/lists/status
//     (dns_reload).

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/radowitz/meridian/internal/lists"
	"github.com/radowitz/meridian/internal/sniff"
)

const (
	defaultDNSReloadWindow = 10 * time.Second
	defaultDNSReloadMinGap = 5 * time.Minute
	dnsReloadFile          = "smartdns-reload.json"
)

// dnsReq is what one pending restart must do.
type dnsReq struct {
	// split: a China list changed; meridian-dns-split is restarted first
	// if the config in force when the restart runs uses it.
	split  bool
	reason string
	// force: restart SmartDNS even with an equal digest (a pending record
	// of an older agent, whose cause is unknown).
	force bool
}

func (q *dnsReq) merge(o dnsReq) {
	q.split = q.split || o.split
	if q.reason == "" {
		q.reason = o.reason
	}
	q.force = q.force || o.force
}

// dnsSnapshot: the SmartDNS files as the agent found them at start.
type dnsSnapshot struct {
	digest string
	newest time.Time // latest modification of a file or directory
	at     time.Time
	err    error
}

type dnsReloader struct {
	mu          sync.Mutex
	loaded      bool
	st          lists.DNSReload
	req         dnsReq // pending, not yet running
	inflight    dnsReq // taken by the running attempt (kept in the record)
	merged      int
	timer       *time.Timer
	running     bool
	lastAttempt time.Time
	boot        *dnsSnapshot
	// known: st.LoadedDigest was set by this process (a managed restart
	// that answered, or the trusted start baseline).
	known bool
}

func (a *Agent) dnsReloadWindow() time.Duration {
	if a.DNSReloadWindow > 0 {
		return a.DNSReloadWindow
	}
	return defaultDNSReloadWindow
}

func (a *Agent) dnsReloadMinGap() time.Duration {
	if a.DNSReloadMinGap > 0 {
		return a.DNSReloadMinGap
	}
	return defaultDNSReloadMinGap
}

func (a *Agent) dnsReloadPath() string {
	return filepath.Join(a.listsDir(), "lists", dnsReloadFile)
}

// dnsReloadBoot records the files at agent start (from init, before any
// publication can run): the start baseline candidate.
func (a *Agent) dnsReloadBoot() {
	at := time.Now()
	d, newest, err := dnsFilesState(a.listsDir())
	r := &a.dnsReload
	r.mu.Lock()
	r.boot = &dnsSnapshot{digest: d, newest: newest, at: at, err: err}
	r.mu.Unlock()
}

// loadLocked reads the saved state once. A restart that was pending when
// the agent stopped is scheduled again with its saved needs; a record
// without a cause (older agent) restarts SmartDNS once and counts as a
// China list change, which restarts meridian-dns-split only if the config
// uses it when the restart runs.
func (a *Agent) dnsReloadLoadLocked() {
	r := &a.dnsReload
	if r.loaded {
		return
	}
	r.loaded = true
	if b, err := os.ReadFile(a.dnsReloadPath()); err == nil {
		_ = json.Unmarshal(b, &r.st)
	}
	if r.st.Last != nil {
		r.lastAttempt = r.st.Last.At
	}
	if r.st.Pending {
		r.merged++
		q := dnsReq{split: r.st.Split, reason: r.st.SplitReason}
		if r.st.Cause != "lists" {
			q = dnsReq{split: true, force: true, reason: r.st.SplitReason}
			if q.reason == "" {
				q.reason = "旧版记录未注明原因"
			}
		}
		r.req.merge(q)
		a.dnsReloadScheduleLocked()
	}
}

// dnsReloadSyncLocked mirrors the pending and running needs into the
// record, so an agent restart resumes them.
func (a *Agent) dnsReloadSyncLocked() {
	r := &a.dnsReload
	q := r.req
	q.merge(r.inflight)
	if !r.st.Pending {
		q = dnsReq{}
	}
	r.st.Split, r.st.SplitReason = q.split, ""
	if q.split {
		r.st.SplitReason = q.reason
	}
	switch {
	case !r.st.Pending:
		r.st.Cause = ""
	case q.force:
		r.st.Cause = "unknown"
	default:
		r.st.Cause = "lists"
	}
}

func (a *Agent) dnsReloadSaveLocked() {
	a.dnsReloadSyncLocked()
	b, err := json.MarshalIndent(a.dnsReload.st, "", "  ")
	if err != nil {
		return
	}
	p := a.dnsReloadPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return
	}
	tmp := p + ".tmp"
	if os.WriteFile(tmp, b, 0o644) == nil {
		_ = os.Rename(tmp, p)
	}
}

// dnsReloadScheduleLocked arms the one timer: the window from now, but not
// before the minimum gap after the previous attempt has passed.
func (a *Agent) dnsReloadScheduleLocked() {
	r := &a.dnsReload
	if r.timer != nil || r.running {
		return
	}
	now := time.Now()
	due := now.Add(a.dnsReloadWindow())
	if !r.lastAttempt.IsZero() {
		if g := r.lastAttempt.Add(a.dnsReloadMinGap()); g.After(due) {
			due = g
		}
	}
	r.st.Pending, r.st.DueAt = true, due.UTC()
	r.timer = time.AfterFunc(due.Sub(now), a.runDNSReload)
}

// resumeDNSReload loads the saved state and re-arms a restart that was
// pending when the previous agent stopped. Idempotent: the state is loaded
// once and an armed or running restart is not scheduled twice.
func (a *Agent) resumeDNSReload() {
	r := &a.dnsReload
	r.mu.Lock()
	defer r.mu.Unlock()
	a.dnsReloadLoadLocked()
}

// splitReasonChnroute: why a list publication needs meridian-dns-split.
const splitReasonChnroute = "China IP 名单（chnroute）已更新"

// requestDNSReload asks for one SmartDNS re-read; split: a China list
// changed (meridian-dns-split is restarted too, regardless of the
// domain-set digest, if the config uses it when the restart runs).
func (a *Agent) requestDNSReload(split bool) {
	r := &a.dnsReload
	r.mu.Lock()
	defer r.mu.Unlock()
	a.dnsReloadLoadLocked()
	r.merged++
	q := dnsReq{split: split}
	if split {
		q.reason = splitReasonChnroute
	}
	r.req.merge(q)
	r.st.Pending = true
	a.dnsReloadScheduleLocked() // no-op while armed or running
	a.dnsReloadSaveLocked()
}

// dnsReloadStatus is the saved state for /v1/lists/status.
func (a *Agent) dnsReloadStatus() *lists.DNSReload {
	r := &a.dnsReload
	r.mu.Lock()
	defer r.mu.Unlock()
	a.dnsReloadLoadLocked()
	if r.st.Last == nil && !r.st.Pending && r.st.LoadedDigest == "" {
		return nil
	}
	st := r.st
	if st.Last != nil {
		l := *st.Last
		st.Last = &l
	}
	return &st
}

// dnsSetLoaded records what SmartDNS loaded. Called with the action lock
// held, after a managed (re)start answered, with the digest taken under
// that lock right before the restart (or the trusted start baseline).
func (a *Agent) dnsSetLoaded(digest string) {
	r := &a.dnsReload
	r.mu.Lock()
	defer r.mu.Unlock()
	a.dnsReloadLoadLocked()
	r.st.LoadedDigest, r.known = digest, true
	a.dnsReloadSaveLocked()
}

// dnsInvalidateLoaded forgets, persistently, what SmartDNS loaded. Called
// with the action lock held right before every managed restart: once the
// restart command runs, the resolver may come up on the new files even if
// the command or the answer check then fails, so the old digest is no
// longer trustworthy. Only a confirmed answer records the new one
// (dnsSetLoaded); until then the next publication restarts conservatively.
func (a *Agent) dnsInvalidateLoaded() {
	r := &a.dnsReload
	r.mu.Lock()
	defer r.mu.Unlock()
	a.dnsReloadLoadLocked()
	r.st.LoadedDigest, r.known = "", true
	a.dnsReloadSaveLocked()
}

func (a *Agent) runDNSReload() {
	r := &a.dnsReload
	r.mu.Lock()
	r.timer, r.running = nil, true
	q, merged := r.req, r.merged
	r.req, r.merged, r.inflight = dnsReq{}, 0, q
	r.mu.Unlock()

	res, skipped := a.doDNSReload(q, merged)

	r.mu.Lock()
	defer r.mu.Unlock()
	r.running, r.inflight = false, dnsReq{}
	r.st.Pending, r.st.DueAt = false, time.Time{}
	if !skipped {
		r.lastAttempt = res.At
		r.st.Last = &res
		if !res.OK && res.Error == errDNSReloadLocked.Error() {
			// Not attempted: try again after the gap.
			r.merged += merged
			r.req.merge(q)
		}
	}
	if r.merged > 0 {
		a.dnsReloadScheduleLocked()
	}
	a.dnsReloadSaveLocked()
}

var errDNSReloadLocked = errors.New("宿主正在执行安装/回滚，SmartDNS 稍后读入")

// dnsBaseline is, under the action lock, what SmartDNS is known to have
// loaded: the digest recorded by this process; else the files found at
// agent start when SmartDNS demonstrably started after their last change
// and before the agent looked at them; else the digest the previous agent
// recorded at its last managed restart. "" (undeterminable) means one
// conservative restart. fromBoot: the start baseline was used.
func (a *Agent) dnsBaseline(x *run, provider string) (digest string, fromBoot bool) {
	r := &a.dnsReload
	r.mu.Lock()
	a.dnsReloadLoadLocked()
	known, saved, boot := r.known, r.st.LoadedDigest, r.boot
	r.mu.Unlock()
	if known {
		return saved, false
	}
	if boot != nil && boot.err == nil {
		if t, ok := x.smartDNSStartedAt(provider); ok && t.After(boot.newest) && !t.After(boot.at) {
			return boot.digest, true
		}
	}
	return saved, false
}

// smartDNSStartedAt: when the running resolver started (second
// resolution for the unit, truncated down, so After() stays strict).
func (x *run) smartDNSStartedAt(provider string) (time.Time, bool) {
	switch provider {
	case "unit":
		out, err := x.cmd(x.a.StepTimeout, "systemctl", "show", "--timestamp=unix", "-p", "ActiveEnterTimestamp", "--value", "smartdns.service")
		v := strings.TrimPrefix(strings.TrimSpace(out), "@")
		var sec int64
		if err != nil || v == "" {
			return time.Time{}, false
		}
		if _, err := fmt.Sscan(v, &sec); err != nil || sec <= 0 {
			return time.Time{}, false
		}
		return time.Unix(sec, 0), true
	case "container":
		out, err := x.cmd(x.a.StepTimeout, "docker", "inspect", "--type", "container", "-f", "{{.State.StartedAt}}", SmartDNSContainer)
		t, perr := time.Parse(time.RFC3339Nano, strings.TrimSpace(out))
		if err != nil || perr != nil || t.Year() < 2000 {
			return time.Time{}, false
		}
		return t, true
	}
	return time.Time{}, false
}

// doDNSReload runs one attempt. skipped: the files equal what SmartDNS
// already loaded and nothing else is needed, nothing ran.
func (a *Agent) doDNSReload(q dnsReq, merged int) (lists.DNSReloadResult, bool) {
	a.init()
	res := lists.DNSReloadResult{At: time.Now().UTC(), Merged: merged}
	ctx, cancel := context.WithTimeout(context.Background(), a.ActionTimeout)
	defer cancel()
	wait, wcancel := context.WithTimeout(ctx, a.LockWait)
	select {
	case a.sem <- struct{}{}:
		wcancel()
	case <-wait.Done():
		wcancel()
		res.Error = errDNSReloadLocked.Error()
		return res, false
	}
	defer func() { <-a.sem }()
	return a.doDNSReloadLocked(ctx, q, res)
}

func (a *Agent) doDNSReloadLocked(ctx context.Context, q dnsReq, res lists.DNSReloadResult) (lists.DNSReloadResult, bool) {
	// Under the lock: no publication, install or rollback changes the
	// files or the recorded baseline until this restart is over.
	digest, err := dnsFilesDigest(a.listsDir())
	if err != nil {
		res.Error = "读取名单文件失败：" + clipShort(err.Error())
		return res, false
	}
	x := &run{a: a, ctx: ctx}
	// The config in force now decides, not the one at publication.
	split := q.split && a.smartDNSUsesDNSSplit()
	provider := x.dnsProvider()
	loaded, fromBoot := a.dnsBaseline(x, provider)
	if digest == loaded && !split && !q.force {
		if fromBoot {
			a.dnsSetLoaded(digest)
		}
		return res, true
	}
	if split {
		if _, err := x.cmd(a.StepTimeout, "systemctl", "restart", DNSSplitUnit); err != nil {
			// Recorded; SmartDNS is still restarted for the new files.
			res.SplitError = "重启 " + DNSSplitUnit + " 失败：" + clipShort(firstLine(err.Error()))
		} else {
			res.SplitRestarted = true
		}
	}
	fail := func(msg string) (lists.DNSReloadResult, bool) {
		res.Error = msg
		if res.SplitError != "" {
			res.Error = res.SplitError + "；" + msg
		}
		return res, false
	}
	var argv []string
	switch provider {
	case "unit":
		res.Target, argv = "smartdns.service", []string{"systemctl", "restart", "smartdns.service"}
	case "container":
		res.Target, argv = SmartDNSContainer, []string{"docker", "restart", SmartDNSContainer}
	default:
		// Nothing runs: it reads the files when it next starts. What it
		// will load is unknown, so the digest is not advanced.
		if res.SplitError != "" {
			res.Error = res.SplitError
			return res, false
		}
		res.OK = true
		return res, false
	}
	a.dnsInvalidateLoaded()
	start := time.Now()
	out, err := x.cmd(a.StepTimeout, argv[0], argv[1:]...)
	res.RestartMS = time.Since(start).Milliseconds()
	if err != nil {
		return fail("重启 " + res.Target + " 失败：" + clipShort(firstLine(strings.TrimSpace(out+" "+err.Error()))))
	}
	if err := a.awaitResolver(ctx); err != nil {
		return fail(res.Target + " 已重启，但 " + err.Error())
	}
	res.AnswerMS = time.Since(start).Milliseconds()
	res.SmartDNSOK = true
	a.dnsSetLoaded(digest)
	if res.SplitError != "" {
		res.Error = res.SplitError + "（" + res.Target + " 已重启并读入名单）"
		return res, false
	}
	res.OK = true
	return res, false
}

// awaitResolver polls 127.0.0.1:53 with the fixed liveness question every
// 300ms until a well-formed reply arrives (DNSLivenessWait, default 20s).
func (a *Agent) awaitResolver(ctx context.Context) error {
	ex := a.DNSCheckExchange
	if ex == nil {
		ex = sniff.ExchangeNet
	}
	wait := dnsLivenessWait
	if a.DNSLivenessWait > 0 {
		wait = a.DNSLivenessWait
	}
	deadline := time.Now().Add(wait)
	for {
		q, id, err := dnsQuery(DNSLivenessName)
		if err == nil {
			cctx, cancel := context.WithTimeout(ctx, min(time.Second, wait))
			var resp []byte
			resp, err = ex(cctx, "127.0.0.1:53", 0, q)
			cancel()
			if err == nil && len(resp) >= 12 && binary.BigEndian.Uint16(resp) == id && resp[2]&0x80 != 0 {
				return nil
			}
		}
		if !time.Now().Before(deadline) || ctx.Err() != nil {
			return fmt.Errorf("%s 内本机 53 端口没有应答", wait.Round(time.Second))
		}
		select {
		case <-ctx.Done():
		case <-time.After(300 * time.Millisecond):
		}
	}
}

// dnsFilesDigest hashes the names and contents of the files SmartDNS reads
// from the lists directory: geosite/ (with ordered/) and keywords/.
func dnsFilesDigest(dir string) (string, error) {
	d, _, err := dnsFilesState(dir)
	return d, err
}

// dnsFilesState is dnsFilesDigest plus the latest modification time of
// those files and their directories (a removal changes a directory).
func dnsFilesState(dir string) (string, time.Time, error) {
	var paths []string
	var newest time.Time
	for _, sub := range []string{"geosite", "keywords"} {
		root := filepath.Join(dir, sub)
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return err
			}
			if d.IsDir() || (d.Type().IsRegular() && strings.HasSuffix(p, ".txt")) {
				if fi, err := d.Info(); err == nil && fi.ModTime().After(newest) {
					newest = fi.ModTime()
				}
			}
			if d.Type().IsRegular() && strings.HasSuffix(p, ".txt") {
				paths = append(paths, p)
			}
			return nil
		})
		if err != nil {
			return "", time.Time{}, err
		}
	}
	sort.Strings(paths)
	h := sha256.New()
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return "", time.Time{}, err
		}
		rel, _ := filepath.Rel(dir, p)
		fmt.Fprintf(h, "%s\x00%d\x00", rel, len(b))
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil)), newest, nil
}
