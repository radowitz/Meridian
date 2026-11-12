package apply

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/hostexec"
)

// Runtime is the host execution boundary. In production it is a
// hostexec.Client talking to meridian-host on the host; tests use fakes.
type Runtime interface {
	Do(ctx context.Context, req hostexec.Request) (hostexec.Result, error)
}

// ErrNoHostExec means an install to the real root was requested but the
// panel has no host execution capability. Nothing on the host is changed.
var ErrNoHostExec = errors.New("面板没有宿主执行能力：安装到本机必须经由宿主上的 meridian-host（host agent）启动服务，已停止，未写入任何宿主文件")

// ErrPending means an earlier host transaction did not finish. New applies
// and rollbacks are refused until Recover has compensated it.
var ErrPending = errors.New("上一次宿主事务没有完成（可能是补偿失败或进程中断），请先执行恢复")

// ErrRuntimeRollbackRequired guards against the old default where the panel
// rollback only swapped data-dir snapshots while the host kept running the
// newer configuration.
var ErrRuntimeRollbackRequired = errors.New("本机已安装 Meridian：回滚必须同时恢复宿主网络（install=true）；只交换数据目录快照需显式 snapshot_only=true")

// ErrMalformedState is returned when a manifest or journal cannot be read.
var ErrMalformedState = errors.New("宿主事务状态文件损坏")

const manifestSchema = 1

// ManagedFile is one host file Meridian owns.
type ManagedFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"` // of the redacted body (placeholder, never the key)
	Mode   string `json:"mode"`
}

// Manifest is the ownership record of everything Meridian installs on one
// host. Only resources listed here are ever removed. Version increases with
// every snapshot.
type Manifest struct {
	Schema      int           `json:"schema"`
	Owner       string        `json:"owner"`
	Node        string        `json:"node"`
	Version     int64         `json:"version"`
	CreatedAt   string        `json:"created_at,omitempty"`
	Canonical   string        `json:"canonical_sha256,omitempty"`
	Files       []ManagedFile `json:"files"`
	Interfaces  []string      `json:"interfaces"`
	Units       []string      `json:"units"`
	NFTTables   []string      `json:"nft_tables"`
	RouteTables []int         `json:"route_tables"`
	Sidecars    []string      `json:"sidecars"`
	DNS         bool          `json:"dns"`
	// Origin is "legacy" for a manifest built by adopting a host installed
	// by a version without manifests (see adoptLegacy); empty otherwise.
	Origin string `json:"origin,omitempty"`
}

// Empty is the state "nothing of Meridian is installed".
func (m Manifest) Empty() bool { return len(m.Files) == 0 }

func (m Manifest) resources() hostexec.Resources {
	return hostexec.Resources{Units: m.Units, Interfaces: m.Interfaces, NFTTables: m.NFTTables, RouteTables: m.RouteTables}
}

func (m Manifest) fileHash(path string) (string, bool) {
	for _, f := range m.Files {
		if f.Path == path {
			return f.SHA256, true
		}
	}
	return "", false
}

var (
	nftTableLine = regexp.MustCompile(`(?m)^table (inet|ip|ip6) ([a-z0-9_]+) \{`)
	rtLine       = regexp.MustCompile(`(?m)^([0-9]+)\s`)
)

// DeriveManifest builds the ownership record of one node's files. Every
// runtime name must pass the host-exec validators, so a manifest can never
// name a resource the agent would not accept.
func DeriveManifest(node string, files map[string]string, version int64, canonical string) (Manifest, error) {
	m := Manifest{Schema: manifestSchema, Owner: "meridian", Node: node, Version: version,
		Files: []ManagedFile{}, Interfaces: []string{}, Units: []string{}, NFTTables: []string{}, RouteTables: []int{}, Sidecars: []string{}}
	if canonical != "" {
		sum := sha256.Sum256([]byte(canonical))
		m.Canonical = hex.EncodeToString(sum[:])
	}
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	units := map[string]bool{}
	for _, p := range paths {
		if strings.Contains(p, "..") || strings.HasPrefix(p, "/") || !allowed(p) {
			return Manifest{}, fmt.Errorf("拒绝受管路径 %s", p)
		}
		sum := sha256.Sum256([]byte(files[p]))
		m.Files = append(m.Files, ManagedFile{Path: p, SHA256: hex.EncodeToString(sum[:]), Mode: fmt.Sprintf("%04o", hostMode(p))})
		dir, base := filepath.Dir(p), filepath.Base(p)
		switch {
		case dir == "etc/wireguard" && strings.HasSuffix(base, ".conf"):
			name := strings.TrimSuffix(base, ".conf")
			if !hostexec.ValidInterface(name) {
				return Manifest{}, fmt.Errorf("接口名 %s 不是受管名称", name)
			}
			m.Interfaces = append(m.Interfaces, name)
		case dir == "etc/systemd/system" && (strings.HasSuffix(base, ".service") || strings.HasSuffix(base, ".timer")):
			if !hostexec.ValidUnit(base) {
				return Manifest{}, fmt.Errorf("unit %s 不是受管名称", base)
			}
			units[base] = true
		case p == "etc/nftables.d/meridian.nft":
			for _, mm := range nftTableLine.FindAllStringSubmatch(files[p], -1) {
				t := mm[1] + " " + mm[2]
				if !hostexec.ValidNFTTable(t) {
					return Manifest{}, fmt.Errorf("nft 表 %s 不是受管名称", t)
				}
				if !contains(m.NFTTables, t) {
					m.NFTTables = append(m.NFTTables, t)
				}
			}
		case p == "etc/iproute2/rt_tables.d/meridian.conf":
			for _, mm := range rtLine.FindAllStringSubmatch(files[p], -1) {
				n, _ := strconv.Atoi(mm[1])
				if !hostexec.ValidRouteTable(n) {
					return Manifest{}, fmt.Errorf("路由表 %d 不是受管表", n)
				}
				m.RouteTables = append(m.RouteTables, n)
			}
		case p == "etc/meridian/mesh-sidecar.compose.yml":
			m.Sidecars = append(m.Sidecars, "mesh")
		case p == "etc/smartdns/smartdns.conf":
			m.DNS = true
		}
	}
	// A timer-driven service is started by its timer, not directly.
	for u := range units {
		if strings.HasSuffix(u, ".service") && units[strings.TrimSuffix(u, ".service")+".timer"] {
			continue
		}
		m.Units = append(m.Units, u)
	}
	sort.Strings(m.Units)
	sort.Strings(m.NFTTables)
	sort.Ints(m.RouteTables)
	return m, nil
}

// ManifestDiff is the before/after difference a host transaction applies.
type ManifestDiff struct {
	FilesAdded         []string `json:"files_added,omitempty"`
	FilesRemoved       []string `json:"files_removed,omitempty"`
	FilesChanged       []string `json:"files_changed,omitempty"`
	InterfacesAdded    []string `json:"interfaces_added,omitempty"`
	InterfacesRemoved  []string `json:"interfaces_removed,omitempty"`
	UnitsAdded         []string `json:"units_added,omitempty"`
	UnitsRemoved       []string `json:"units_removed,omitempty"`
	NFTTablesAdded     []string `json:"nft_tables_added,omitempty"`
	NFTTablesRemoved   []string `json:"nft_tables_removed,omitempty"`
	RouteTablesAdded   []int    `json:"route_tables_added,omitempty"`
	RouteTablesRemoved []int    `json:"route_tables_removed,omitempty"`
	SidecarsAdded      []string `json:"sidecars_added,omitempty"`
	SidecarsRemoved    []string `json:"sidecars_removed,omitempty"`
}

func DiffManifests(from, to Manifest) ManifestDiff {
	var d ManifestDiff
	for _, f := range to.Files {
		if h, ok := from.fileHash(f.Path); !ok {
			d.FilesAdded = append(d.FilesAdded, f.Path)
		} else if h != f.SHA256 {
			d.FilesChanged = append(d.FilesChanged, f.Path)
		}
	}
	for _, f := range from.Files {
		if _, ok := to.fileHash(f.Path); !ok {
			d.FilesRemoved = append(d.FilesRemoved, f.Path)
		}
	}
	d.InterfacesAdded, d.InterfacesRemoved = minus(to.Interfaces, from.Interfaces), minus(from.Interfaces, to.Interfaces)
	d.UnitsAdded, d.UnitsRemoved = minus(to.Units, from.Units), minus(from.Units, to.Units)
	d.NFTTablesAdded, d.NFTTablesRemoved = minus(to.NFTTables, from.NFTTables), minus(from.NFTTables, to.NFTTables)
	d.RouteTablesAdded, d.RouteTablesRemoved = minusInt(to.RouteTables, from.RouteTables), minusInt(from.RouteTables, to.RouteTables)
	d.SidecarsAdded, d.SidecarsRemoved = minus(to.Sidecars, from.Sidecars), minus(from.Sidecars, to.Sidecars)
	return d
}

func minus(a, b []string) []string {
	var out []string
	for _, s := range a {
		if !contains(b, s) {
			out = append(out, s)
		}
	}
	return out
}

func minusInt(a, b []int) []int {
	var out []int
	for _, n := range a {
		found := false
		for _, m := range b {
			found = found || n == m
		}
		if !found {
			out = append(out, n)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// HostReport describes one host transaction for the panel.
type HostReport struct {
	Transaction string          `json:"transaction"`
	Kind        string          `json:"kind"`
	FromVersion int64           `json:"from_version"`
	ToVersion   int64           `json:"to_version"`
	Diff        ManifestDiff    `json:"diff"`
	Steps       []hostexec.Step `json:"steps,omitempty"`
	Warnings    []string        `json:"warnings,omitempty"`
	Committed   bool            `json:"committed"`
	Compensated bool            `json:"compensated,omitempty"`
}

// TxnError is a failed host transaction. Compensated reports whether the
// host and the data directory were restored to the state before it; when
// false the journal is kept and ErrPending blocks new work until Recover.
type TxnError struct {
	Op          string
	Err         error
	Compensated bool
	CompErr     error
	Report      *HostReport
}

func (e *TxnError) Error() string {
	if e.Compensated {
		return fmt.Sprintf("%s失败，已补偿回到事务前的状态：%v", e.Op, e.Err)
	}
	if e.CompErr != nil {
		return fmt.Sprintf("%s失败：%v；补偿也失败：%v。宿主处于未知状态，事务日志已保留，请修复后执行恢复", e.Op, e.Err, e.CompErr)
	}
	return fmt.Sprintf("%s失败：%v", e.Op, e.Err)
}

func (e *TxnError) Unwrap() error { return e.Err }

type snapPair struct {
	Applied  int64 `json:"applied"`  // -1: absent
	Previous int64 `json:"previous"` // -1: absent
}

// journal is the persistent record of an in-flight transaction.
type journal struct {
	ID      string   `json:"id"`
	Kind    string   `json:"kind"` // apply | rollback | snapshot
	Install bool     `json:"install"`
	Phase   string   `json:"phase"` // prepared | host | commit | compensate
	Attempt int      `json:"attempt"`
	From    Manifest `json:"from"`
	To      Manifest `json:"to"`
	Before  snapPair `json:"before"`
	After   snapPair `json:"after"`
	Started string   `json:"started"`
	Error   string   `json:"error,omitempty"`
}

const (
	phasePrepared   = "prepared"
	phaseHost       = "host"
	phaseCommit     = "commit"
	phaseCompensate = "compensate"
)

// PendingView is what the panel shows about an unfinished transaction.
type PendingView struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Phase   string `json:"phase"`
	Error   string `json:"error,omitempty"`
	Started string `json:"started"`
	From    int64  `json:"from_version"`
	To      int64  `json:"to_version"`
}

func (a Applier) hostDir() string     { return filepath.Join(a.data(), "host") }
func (a Applier) journalPath() string { return filepath.Join(a.hostDir(), "journal.json") }
func (a Applier) holdDir() string     { return filepath.Join(a.hostDir(), "hold") }
func (a Applier) installedDir() string {
	return filepath.Join(a.hostDir(), "installed")
}
func (a Applier) nextDir() string { return filepath.Join(a.hostDir(), "next") }

func (a Applier) loadJournal() (*journal, error) {
	b, err := os.ReadFile(a.journalPath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var j journal
	if err := json.Unmarshal(b, &j); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedState, err)
	}
	return &j, nil
}

func (a Applier) saveJournal(j *journal) error {
	b, _ := json.MarshalIndent(j, "", "  ")
	return writeDurable(a.journalPath(), b, 0o600)
}

func (a Applier) dropJournal() error {
	err := os.Remove(a.journalPath())
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return syncDir(a.hostDir())
}

// Pending returns the unfinished transaction, if any.
func (a Applier) Pending() (*PendingView, error) {
	j, err := a.loadJournal()
	if err != nil || j == nil {
		return nil, err
	}
	return &PendingView{ID: j.ID, Kind: j.Kind, Phase: j.Phase, Error: j.Error, Started: j.Started, From: j.From.Version, To: j.To.Version}, nil
}

// Installed returns the manifest of what is installed on the host, or an
// empty manifest when nothing is.
func (a Applier) Installed() (Manifest, error) {
	return readManifest(a.installedDir())
}

func readManifest(dir string) (Manifest, error) {
	b, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if os.IsNotExist(err) {
		return Manifest{}, nil
	}
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return Manifest{}, fmt.Errorf("%w: %v", ErrMalformedState, err)
	}
	return m, nil
}

func writeManifest(dir string, m Manifest) error {
	b, _ := json.MarshalIndent(m, "", "  ")
	return writeDurable(filepath.Join(dir, "manifest.json"), b, 0o644)
}

// snapVersion: -1 when dir is absent, 0 for a snapshot from before manifests.
func snapVersion(dir string) int64 {
	if _, err := os.Stat(dir); err != nil {
		return -1
	}
	m, err := readManifest(dir)
	if err != nil {
		return 0
	}
	return m.Version
}

func (a Applier) snapshots() snapPair {
	return snapPair{Applied: snapVersion(filepath.Join(a.data(), "applied")), Previous: snapVersion(filepath.Join(a.data(), "previous"))}
}

// upgradeLegacy gives snapshots written before manifests existed a version,
// so the version-addressed arrange below can find them.
func (a Applier) upgradeLegacy() error {
	prev := filepath.Join(a.data(), "previous")
	app := filepath.Join(a.data(), "applied")
	pv := snapVersion(prev)
	if pv == 0 {
		if err := a.writeSnapshotManifest(prev, 1); err != nil {
			return err
		}
		pv = 1
	}
	if snapVersion(app) == 0 {
		v := int64(1)
		if pv > 0 {
			v = pv + 1
		}
		if err := a.writeSnapshotManifest(app, v); err != nil {
			return err
		}
	}
	return nil
}

func (a Applier) writeSnapshotManifest(dir string, version int64) error {
	files, err := readNodeFiles(dir, a.localID())
	if err != nil {
		return err
	}
	canon, _ := os.ReadFile(filepath.Join(dir, "canonical.txt"))
	m, err := DeriveManifest(a.localID(), files, version, string(canon))
	if err != nil {
		return err
	}
	return writeManifest(dir, m)
}

func (a Applier) nextVersion() int64 {
	v := int64(0)
	s := a.snapshots()
	inst, _ := a.Installed()
	for _, n := range []int64{s.Applied, s.Previous, inst.Version} {
		if n > v {
			v = n
		}
	}
	return v + 1
}

// arrange puts the snapshot with version want.Applied at applied/ and
// want.Previous at previous/ (-1: absent). It only renames inside the data
// dir and is idempotent, so a crash part-way is finished by running it again.
func (a Applier) arrange(want snapPair) error {
	root := a.data()
	app, prev := filepath.Join(root, "applied"), filepath.Join(root, "previous")
	if snapVersion(app) == want.Applied && snapVersion(prev) == want.Previous {
		return nil
	}
	hold := a.holdDir()
	if err := os.MkdirAll(hold, 0o750); err != nil {
		return err
	}
	for _, d := range []string{app, prev} {
		if v := snapVersion(d); v >= 0 {
			if err := os.Rename(d, filepath.Join(hold, fmt.Sprintf("snap-%d-%s", v, randID()))); err != nil {
				return err
			}
		}
	}
	pick := func(v int64, dest string) error {
		if v < 0 {
			return nil
		}
		entries, err := os.ReadDir(hold)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if !strings.HasPrefix(e.Name(), "snap-") {
				continue
			}
			src := filepath.Join(hold, e.Name())
			if snapVersion(src) == v {
				return os.Rename(src, dest)
			}
		}
		return fmt.Errorf("找不到版本 %d 的快照", v)
	}
	if err := pick(want.Applied, app); err != nil {
		return err
	}
	if err := pick(want.Previous, prev); err != nil {
		return err
	}
	return syncDir(root)
}

// cleanHold drops set-aside snapshots. Only called with no journal present.
func (a Applier) cleanHold() error {
	return os.RemoveAll(a.holdDir())
}

func randID() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func newTxnID() string {
	return "tx-" + time.Now().UTC().Format("20060102T150405") + "-" + randID()
}

// writeInstalledCopy keeps a redacted copy of the node files a transaction
// installs, so compensation can restore them even after the data-dir
// snapshots have rotated past that version.
func writeInstalledCopy(dir, node string, files map[string]string, m Manifest) error {
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	for p, body := range files {
		dest := filepath.Join(dir, "nodes", node, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
			return err
		}
		if err := os.WriteFile(dest, []byte(body), 0o640); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	return writeManifest(dir, m)
}

type txn struct {
	a       Applier
	j       *journal
	toFiles map[string]string // redacted node files of j.To (install only)
	rt      Runtime
	rep     *HostReport
}

func (a Applier) newReport(j *journal) *HostReport {
	return &HostReport{Transaction: j.ID, Kind: j.Kind, FromVersion: j.From.Version, ToVersion: j.To.Version, Diff: DiffManifests(j.From, j.To)}
}

// execute runs a prepared transaction to commit, or compensates it.
func (t *txn) execute(op string) error {
	a := t.a
	if err := a.saveJournal(t.j); err != nil {
		return err
	}
	if t.j.Install {
		if err := writeInstalledCopy(a.nextDir(), a.localID(), t.toFiles, t.j.To); err != nil {
			return t.abort(op, err)
		}
	}
	if err := a.arrange(t.j.After); err != nil {
		return t.abort(op, err)
	}
	if t.j.Install {
		t.j.Phase = phaseHost
		if err := a.saveJournal(t.j); err != nil {
			return t.abort(op, err)
		}
		if err := t.converge(t.j.From, t.j.To, t.toFiles, "fwd"); err != nil {
			return t.abort(op, err)
		}
	}
	t.j.Phase = phaseCommit
	if err := a.saveJournal(t.j); err != nil {
		return t.abort(op, err)
	}
	if err := t.commit(); err != nil {
		// The host is converged; only bookkeeping failed. The journal says
		// "commit", so Recover finishes it rather than undoing the host.
		return &TxnError{Op: op, Err: fmt.Errorf("宿主已生效但提交记录失败：%w", err), Report: t.rep}
	}
	t.rep.Committed = true
	return nil
}

func (t *txn) commit() error {
	a := t.a
	if err := a.arrange(t.j.After); err != nil {
		return err
	}
	if t.j.Install {
		inst, next := a.installedDir(), a.nextDir()
		if _, err := os.Stat(next); err == nil {
			if v := snapVersion(inst); v >= 0 {
				if err := os.MkdirAll(a.holdDir(), 0o750); err != nil {
					return err
				}
				if err := os.Rename(inst, filepath.Join(a.holdDir(), fmt.Sprintf("installed-%d-%s", v, randID()))); err != nil {
					return err
				}
			}
			if t.j.To.Empty() {
				if err := os.RemoveAll(next); err != nil {
					return err
				}
			} else if err := os.Rename(next, inst); err != nil {
				return err
			}
		}
		if err := syncDir(a.hostDir()); err != nil {
			return err
		}
	}
	if err := a.dropJournal(); err != nil {
		return err
	}
	return a.cleanHold()
}

// abort compensates: the host goes back to j.From and the snapshots to
// j.Before. Only when that fully succeeds is the journal removed.
func (t *txn) abort(op string, cause error) error {
	a := t.a
	t.j.Phase = phaseCompensate
	t.j.Attempt++
	if t.j.Error == "" {
		t.j.Error = a.redactErr(cause).Error()
	}
	if err := a.saveJournal(t.j); err != nil {
		return &TxnError{Op: op, Err: cause, CompErr: err, Report: t.rep}
	}
	if err := t.compensate(); err != nil {
		t.j.Error = a.redactErr(cause).Error() + "；补偿失败：" + a.redactErr(err).Error()
		_ = a.saveJournal(t.j)
		return &TxnError{Op: op, Err: a.redactErr(cause), CompErr: a.redactErr(err), Report: t.rep}
	}
	t.rep.Compensated = true
	return &TxnError{Op: op, Err: a.redactErr(cause), Compensated: true, Report: t.rep}
}

func (t *txn) compensate() error {
	a := t.a
	if t.j.Install {
		fromFiles := map[string]string{}
		if !t.j.From.Empty() {
			var err error
			fromFiles, err = readNodeFiles(a.installedDir(), a.localID())
			if err != nil {
				return err
			}
			if v := snapVersion(a.installedDir()); v != t.j.From.Version {
				return fmt.Errorf("已安装副本版本 %d 与事务记录的 %d 不一致", v, t.j.From.Version)
			}
		}
		if err := t.converge(t.j.To, t.j.From, fromFiles, "comp"); err != nil {
			return err
		}
	}
	if err := a.arrange(t.j.Before); err != nil {
		return err
	}
	if err := os.RemoveAll(a.nextDir()); err != nil {
		return err
	}
	if err := a.dropJournal(); err != nil {
		return err
	}
	return a.cleanHold()
}

func (t *txn) reqID(tag string) string {
	return fmt.Sprintf("%s/%d/%s", t.j.ID, t.j.Attempt, tag)
}

func (t *txn) call(action, tag string, r hostexec.Resources) error {
	if t.rt == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	res, err := t.rt.Do(ctx, hostexec.Request{Action: action, RequestID: t.reqID(tag), Resources: r})
	t.rep.Steps = append(t.rep.Steps, res.Steps...)
	t.rep.Warnings = append(t.rep.Warnings, res.Warnings...)
	if err != nil {
		return err
	}
	if !res.OK {
		return fmt.Errorf("宿主动作 %s 失败：%s", action, res.Error)
	}
	return nil
}

// converge moves the host from one manifest to another: remove runtime
// resources only "from" owns, delete files only "from" owns, write the
// target files, then activate the target (daemon-reload, meridian.service,
// units, health). Every step is idempotent, so a retry or a restart can run
// it again. Nothing outside the two manifests is touched.
func (t *txn) converge(from, to Manifest, toFiles map[string]string, tag string) error {
	a := t.a
	if len(to.Sidecars) > 0 || len(minus(from.Sidecars, to.Sidecars)) > 0 {
		return errors.New("本机 host agent 不管理 Mesh sidecar；网关不应运行 sidecar")
	}
	rm := hostexec.Resources{
		Units:       minus(from.Units, to.Units),
		Interfaces:  minus(from.Interfaces, to.Interfaces),
		NFTTables:   minus(from.NFTTables, to.NFTTables),
		RouteTables: minusInt(from.RouteTables, to.RouteTables),
	}
	if !rm.Empty() {
		if err := t.call(hostexec.ActionRollback, tag+"-remove", rm); err != nil {
			return err
		}
	}
	root := a.hostRoot()
	for _, f := range from.Files {
		if _, keep := to.fileHash(f.Path); keep {
			continue
		}
		if strings.Contains(f.Path, "..") || strings.HasPrefix(f.Path, "/") || !allowed(f.Path) {
			return fmt.Errorf("拒绝删除路径 %s", f.Path)
		}
		if err := os.Remove(filepath.Join(root, filepath.FromSlash(f.Path))); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	planned, err := a.prepareHost(toFiles)
	if err != nil {
		return err
	}
	for _, f := range planned {
		if err := writeHostFile(filepath.Join(root, filepath.FromSlash(f.rel)), f.body, f.mode); err != nil {
			return err
		}
	}
	if to.Empty() {
		return nil
	}
	r := to.resources()
	// Restart the resolver only when its config is new or changed.
	if to.DNS {
		h, _ := to.fileHash("etc/smartdns/smartdns.conf")
		old, ok := from.fileHash("etc/smartdns/smartdns.conf")
		r.DNS = !ok || old != h
	}
	return t.call(hostexec.ActionActivate, tag+"-activate", r)
}

// funcRuntime adapts the legacy Activate hook: activate calls it, health
// and removal succeed. Tests only.
type funcRuntime func() error

func (f funcRuntime) Do(_ context.Context, req hostexec.Request) (hostexec.Result, error) {
	res := hostexec.Result{RequestID: req.RequestID, Action: req.Action, OK: true}
	if req.Action == hostexec.ActionActivate {
		if err := f(); err != nil {
			res.OK = false
			res.Error = err.Error()
			return res, err
		}
	}
	return res, nil
}

func writeDurable(path string, b []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer d.Close()
	_ = d.Sync() // best effort; not all filesystems support it
	return nil
}

// ErrLegacyInstall means the host runs a Meridian data plane installed by a
// version without manifests, and it cannot be adopted reliably. Nothing on
// the host, in the snapshots or in the data directory was changed.
var ErrLegacyInstall = errors.New("宿主上有旧版 Meridian 数据面（没有受管清单），无法可靠接管；已停止，宿主、快照和数据目录都没有改动")

var (
	privateKeyLine = regexp.MustCompile(`(?m)^[ \t]*PrivateKey[ \t]*=[ \t]*(\S+)[ \t]*$`)
	bootForwarding = regexp.MustCompile(`(?m)^([ \t]*net\.(?:ipv4\.ip_forward|ipv6\.conf\.all\.forwarding)[ \t]*=[ \t]*)0([ \t]*)$`)
)

func (a Applier) forwardingOn() bool {
	f := a.Forwarding
	if f == nil {
		if filepath.Clean(a.hostRoot()) != "/" {
			return false
		}
		f = hostexec.ProcForwarding
	}
	on, err := f()
	return err == nil && on
}

// legacyCandidates lists host paths an older version may have installed:
// the gateway files of the old snapshots, the files about to be written,
// and Meridian-named files found on the host.
func (a Applier) legacyCandidates(to map[string]string) []string {
	set := map[string]bool{}
	for p := range to {
		set[p] = true
	}
	for _, snap := range []string{"applied", "previous"} {
		if files, err := readNodeFiles(filepath.Join(a.data(), snap), a.localID()); err == nil {
			for p := range files {
				set[p] = true
			}
		}
	}
	root := a.hostRoot()
	scan := func(dir string, keep func(string) bool) {
		entries, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(dir)))
		if err != nil {
			return
		}
		for _, e := range entries {
			if keep(e.Name()) {
				set[dir+"/"+e.Name()] = true
			}
		}
	}
	scan("etc/wireguard", func(n string) bool {
		return strings.HasSuffix(n, ".conf") && hostexec.ValidInterface(strings.TrimSuffix(n, ".conf"))
	})
	scan("usr/local/sbin", func(n string) bool { return strings.HasPrefix(n, "meridian-") })
	scan("etc/nftables.d", func(n string) bool { return strings.HasPrefix(n, "meridian") && strings.HasSuffix(n, ".nft") })
	scan("etc/systemd/system", hostexec.ValidUnit)
	for _, p := range []string{"etc/iproute2/rt_tables.d/meridian.conf", "etc/sysctl.d/99-meridian.conf", "etc/meridian/forwarding.conf"} {
		set[p] = true
	}
	out := make([]string, 0, len(set))
	for p := range set {
		if allowed(p) && !strings.Contains(p, "..") {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// adoptLegacy runs inside the transaction lock, before anything changes,
// when the host has no installed manifest. If an older version's data plane
// is on the host (meridian-up.sh exists), it records what is actually there
// as the installed manifest (origin "legacy") with a restore copy, so a
// failed first install compensates back to the old, running data plane.
// It refuses, changing nothing, when that cannot be done reliably: a
// WireGuard config whose private key is not the gateway key the panel
// holds, a file that is not a regular file or names a resource the host
// agent would not accept, old resources the new configuration would have
// to remove, or an old data plane that is not healthy. to are the node
// files the transaction will install. The returned notes go into the
// transaction report.
func (a Applier) adoptLegacy(rt Runtime, to map[string]string) ([]string, error) {
	inst, err := a.Installed()
	if err != nil || !inst.Empty() {
		return nil, err
	}
	root := a.hostRoot()
	if fi, err := os.Stat(filepath.Join(root, "usr", "local", "sbin", "meridian-up.sh")); err != nil || !fi.Mode().IsRegular() {
		return nil, nil
	}
	refuse := func(format string, args ...any) error {
		return fmt.Errorf("%w：%s", ErrLegacyInstall, fmt.Sprintf(format, args...))
	}
	files := map[string]string{}
	var found []string
	for _, rel := range a.legacyCandidates(to) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		fi, err := os.Lstat(p)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, refuse("读取 /%s 失败：%v", rel, err)
		}
		if !fi.Mode().IsRegular() {
			return nil, refuse("/%s 不是普通文件", rel)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, refuse("读取 /%s 失败：%v", rel, err)
		}
		files[rel] = string(b)
		found = append(found, "/"+rel)
	}
	// The restore copy never holds a private key: it must be the gateway
	// key, which the install boundary injects again (byte-identical).
	for rel, body := range files {
		if !isWireGuardConf(rel) {
			continue
		}
		m := privateKeyLine.FindAllStringSubmatch(body, -1)
		switch {
		case len(m) != 1:
			return nil, refuse("/%s 没有唯一的 PrivateKey 行", rel)
		case a.PrivateKey == "" || m[0][1] != a.PrivateKey:
			return nil, refuse("/%s 的私钥不是面板保存的网关私钥（或仍是占位符）；面板不能另存这把私钥，也就不能保证恢复。"+
				"把旧版的私钥填进网关节点，或在宿主上停用旧版后再安装", rel)
		}
		files[rel] = strings.ReplaceAll(body, a.PrivateKey, compile.PrivateKeyPlaceholder)
	}
	var notes []string
	// The old meridian-up.sh applies 99-meridian.conf, forwarding included.
	// install.sh's upgrade rewrites its boot-time forwarding lines to 0:
	// restarting the old version from that file would leave forwarding off.
	if _, newer := files["etc/meridian/forwarding.conf"]; !newer {
		if body, ok := files["etc/sysctl.d/99-meridian.conf"]; ok && bootForwarding.MatchString(body) && a.forwardingOn() {
			files["etc/sysctl.d/99-meridian.conf"] = bootForwarding.ReplaceAllString(body, "${1}1${2}")
			notes = append(notes, "旧版恢复副本里 99-meridian.conf 的转发行记为 1：接管时双栈转发是打开的，旧版启动脚本按这个文件设置转发")
		}
	}
	m, err := DeriveManifest(a.localID(), files, a.nextVersion(), "")
	if err != nil {
		return nil, refuse("%v", err)
	}
	m.Origin = "legacy"
	m.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	if len(m.Sidecars) > 0 {
		return nil, refuse("旧版在网关上留有 Mesh sidecar 配置")
	}
	target, err := DeriveManifest(a.localID(), to, 0, "")
	if err != nil {
		return nil, err
	}
	if extra := append(minus(m.Units, target.Units), minus(m.Interfaces, target.Interfaces)...); len(extra) > 0 {
		return nil, refuse("旧版运行着新配置不再包含的 %s；宿主 agent 只移除自己激活过的资源。先保留它们完成这次安装，下一次安装再删除",
			strings.Join(extra, "、"))
	}
	if rt != nil {
		r := m.resources()
		r.DNS = m.DNS
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		res, err := rt.Do(ctx, hostexec.Request{Action: hostexec.ActionHealth, RequestID: "adopt-" + randID(), Resources: r})
		cancel()
		if err != nil || !res.OK {
			var failed []string
			for _, st := range res.Steps {
				if !st.OK && !st.Skipped {
					failed = append(failed, st.Name)
				}
			}
			if err != nil && len(failed) == 0 {
				failed = append(failed, err.Error())
			}
			return nil, refuse("旧版数据面不健康（%s），没有可恢复的运行状态。修好旧版或在宿主上停用它后再安装；发现的旧版文件：%s",
				strings.Join(failed, "；"), strings.Join(found, " "))
		}
	}
	// Write the restore copy beside installed/ and rename it into place:
	// a crash leaves either no manifest (adoption runs again) or a whole one.
	tmp := filepath.Join(a.hostDir(), "adopt-"+randID())
	if err := writeInstalledCopy(tmp, a.localID(), files, m); err != nil {
		_ = os.RemoveAll(tmp)
		return nil, err
	}
	if err := os.RemoveAll(a.installedDir()); err != nil {
		_ = os.RemoveAll(tmp)
		return nil, err
	}
	if err := os.Rename(tmp, a.installedDir()); err != nil {
		_ = os.RemoveAll(tmp)
		return nil, err
	}
	if err := syncDir(a.hostDir()); err != nil {
		return nil, err
	}
	notes = append([]string{fmt.Sprintf("已接管旧版安装（清单版本 %d，%d 个文件）：失败时补偿恢复到旧版并重新激活", m.Version, len(m.Files))}, notes...)
	return notes, nil
}
