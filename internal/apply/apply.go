// Package apply stores rendered bundles, diffs them, and installs the
// gateway's files and runtime as one persistent transaction (see txn.go)
// without touching anything Meridian does not own.
package apply

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/hostexec"
)

// Allowed prefixes are the only paths an install may write on a node.
var allowedPrefixes = []string{
	"etc/wireguard/",
	"etc/nftables.d/",
	"etc/sysctl.d/",
	"etc/systemd/system/",
	"etc/smartdns/",
	"etc/iproute2/rt_tables.d/",
	"usr/local/sbin/",
	"etc/meridian/",
}

type Result struct {
	DryRun  bool     `json:"dry_run"`
	Install bool     `json:"install"`
	Wrote   []string `json:"wrote"`
	Order   []string `json:"order"`
	Diff    string   `json:"diff"`
	// Host describes the host transaction of an install or runtime rollback:
	// manifest versions, the before/after resource difference, the agent's
	// steps and warnings.
	Host *HostReport `json:"host,omitempty"`
}

type Applier struct {
	DataDir string
	// Install copies the local gateway files into the host and activates them
	// through Host as one persistent transaction.
	Install bool
	// SnapshotOnly allows a rollback without Install even though the host has
	// an installed manifest. Without it such a rollback is refused.
	SnapshotOnly bool
	// LocalID is the node whose files are installed on this host (the gateway).
	LocalID string
	// PrivateKey is LocalID's WireGuard private key. It is injected only while
	// writing etc/wireguard/ files to the host (mode 0600). Snapshots under
	// DataDir, the canonical text, diffs and Result keep the placeholder.
	// An install whose WireGuard files still need a key fails before any host
	// file is written when this is empty or malformed.
	PrivateKey string
	// Secrets are the credential-store WireGuard secrets (remote-access
	// private key, pre-shared keys) by id. Like PrivateKey they are injected
	// only while writing etc/wireguard/ files to the host; every other copy
	// keeps the __MERIDIAN_SECRET_<id>__ placeholder. A placeholder whose id
	// is missing fails before any host file is written.
	Secrets map[string]string
	// HostRoot is where installs write. Empty means "/". Tests use a temp dir.
	HostRoot string
	// Host is the host execution boundary (hostexec.Client). An install to
	// the real root without it fails with ErrNoHostExec before anything is
	// written. With a temp HostRoot and no Host, only files are written.
	Host Runtime
	// Activate is a test shim: when Host is nil, a Runtime whose activate
	// calls this function (health and removal succeed).
	Activate func() error
	// Artifacts are the panel-delivered binaries (artifacts.Bundle) and Arch
	// the host's architecture (uname -m). With Artifacts set, an install
	// whose units run a binary installs the verified copy as part of the
	// transaction and refuses before writing anything when it is not
	// available. Nil: binaries are not managed by this Applier.
	Artifacts ArtifactSource
	Arch      string
	// Forwarding reports whether IPv4 and IPv6 forwarding are both on (used
	// when adopting a legacy install). Nil: /proc on the real root, "off"
	// for a test HostRoot.
	Forwarding func() (bool, error)
	// ReadSysctl reads one kernel key for the install's sysctl report
	// (SysctlReport). Nil: /proc/sys on the real root, not read for a test
	// HostRoot.
	ReadSysctl func(key string) (string, error)
}

func (a Applier) hostRoot() string {
	if a.HostRoot == "" {
		return "/"
	}
	return a.HostRoot
}

func (a Applier) data() string {
	if a.DataDir != "" {
		return a.DataDir
	}
	return "/var/lib/meridian"
}

func (a Applier) localID() string {
	if a.LocalID != "" {
		return a.LocalID
	}
	return "gw"
}

// runtime picks the host boundary. A nil Runtime with a nil error means
// "files only" and is only possible with a non-root HostRoot.
func (a Applier) runtime() (Runtime, error) {
	if a.Host != nil {
		return a.Host, nil
	}
	if a.Activate != nil {
		return funcRuntime(a.Activate), nil
	}
	if filepath.Clean(a.hostRoot()) == "/" {
		return nil, ErrNoHostExec
	}
	return nil, nil
}

// probe proves the host boundary is reachable and authenticated before any
// snapshot rotates or host file changes.
func (a Applier) probe(rt Runtime) error {
	if rt == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := rt.Do(ctx, hostexec.Request{Action: hostexec.ActionHealth, RequestID: "probe-" + randID()}); err != nil {
		if errors.Is(err, hostexec.ErrUnavailable) {
			return fmt.Errorf("%w（%v）", ErrNoHostExec, err)
		}
		return fmt.Errorf("%w：%w", ErrHostAgentFailed, err)
	}
	return nil
}

// PreviousAvailable reports whether a previous snapshot exists, i.e.
// whether a rollback has anything to go back to. Read-only.
func (a Applier) PreviousAvailable() bool {
	fi, err := os.Stat(filepath.Join(a.data(), "previous"))
	return err == nil && fi.IsDir()
}

// InstalledDiff compares what installing b would put on this host with the
// installed manifest, by file hash (installed copies carry the same
// placeholders as the bundle, so the hashes are comparable). It returns nil
// when nothing is installed. Content diffs against the installed copy are
// not offered: only names and hashes.
func (a Applier) InstalledDiff(b *compile.Bundle) (*ManifestDiff, error) {
	inst, err := a.Installed()
	if err != nil || inst.Empty() {
		return nil, err
	}
	to, err := DeriveManifest(a.localID(), nodeFiles(b.Files, a.localID()), 0, "")
	if err != nil {
		return nil, err
	}
	d := DiffManifests(inst, to)
	return &d, nil
}

// Diff compares the last applied canonical text with the candidate.
func (a Applier) Diff(next string) (string, error) {
	prev, err := os.ReadFile(filepath.Join(a.data(), "applied", "canonical.txt"))
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	return Unified(string(prev), next), nil
}

// AppliedCanonical returns the canonical text of the last applied snapshot
// ("", false when nothing was applied yet). Read-only.
func (a Applier) AppliedCanonical() (string, bool, error) {
	b, err := os.ReadFile(filepath.Join(a.data(), "applied", "canonical.txt"))
	if os.IsNotExist(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return string(b), true, nil
}

// begin takes the transaction lock and refuses to start while an earlier
// transaction is unfinished. The returned func releases the lock.
func (a Applier) begin() (func(), error) {
	if err := os.MkdirAll(a.hostDir(), 0o750); err != nil {
		return nil, err
	}
	unlock, err := lockFile(filepath.Join(a.hostDir(), "txn.lock"))
	if err != nil {
		return nil, err
	}
	j, err := a.loadJournal()
	if err != nil {
		unlock()
		return nil, err
	}
	if j != nil {
		unlock()
		return nil, fmt.Errorf("%w（事务 %s，阶段 %s）", ErrPending, j.ID, j.Phase)
	}
	if err := a.cleanHold(); err != nil {
		unlock()
		return nil, err
	}
	if err := a.upgradeLegacy(); err != nil {
		unlock()
		return nil, err
	}
	return unlock, nil
}

// Apply records the bundle. When Install is set, the gateway files are
// installed and activated as one transaction with the snapshot rotation:
// on any failure the host and the data directory are compensated back.
func (a Applier) Apply(b *compile.Bundle, dryRun bool) (Result, error) {
	canon := b.Canonical()
	diff, err := a.Diff(canon)
	if err != nil {
		return Result{}, err
	}
	res := Result{DryRun: dryRun, Install: a.Install && !dryRun, Order: b.Order, Diff: diff}
	if dryRun {
		return res, nil
	}
	local := nodeFiles(b.Files, a.localID())
	var rt Runtime
	if a.Install {
		// Resolve the private key, every host path and the host boundary
		// before the snapshot rotates or any host config is overwritten.
		if _, err := a.prepareHost(local); err != nil {
			return Result{}, err
		}
		if rt, err = a.runtime(); err != nil {
			return Result{}, err
		}
	}
	unlock, err := a.begin()
	if err != nil {
		return Result{}, err
	}
	defer unlock()
	var notes []string
	if a.Install {
		if err := a.probe(rt); err != nil {
			return Result{}, err
		}
		// A host installed by a version without manifests is adopted (or
		// refused) before anything is written.
		if notes, err = a.adoptLegacy(rt, local); err != nil {
			return Result{}, err
		}
	}
	version := a.nextVersion()
	to, err := DeriveManifest(a.localID(), local, version, canon)
	if err != nil {
		return Result{}, err
	}
	if a.Install {
		if to.Artifacts, err = a.planArtifacts(local); err != nil {
			return Result{}, err
		}
	}
	if a.Install && len(to.Sidecars) > 0 {
		return Result{}, errors.New("本机 host agent 不管理 Mesh sidecar；网关不应运行 sidecar")
	}
	from, err := a.Installed()
	if err != nil {
		return Result{}, err
	}
	j := &journal{ID: newTxnID(), Kind: "snapshot", Install: a.Install, Phase: phasePrepared,
		From: from, To: to, Before: a.snapshots(), Started: time.Now().UTC().Format(time.RFC3339)}
	if a.Install {
		j.Kind = "apply"
	}
	j.After = snapPair{Applied: version, Previous: j.Before.Applied}
	to.CreatedAt = j.Started
	j.To = to

	// Stage the snapshot beside the others; arrange moves it into place.
	stage := filepath.Join(a.holdDir(), fmt.Sprintf("snap-%d-%s", version, randID()))
	var wrote []string
	for path, body := range b.Files {
		rel, err := safeBundlePath(path)
		if err != nil {
			return Result{}, err
		}
		dest := filepath.Join(stage, rel)
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return Result{}, err
		}
		mode := os.FileMode(0o644)
		if strings.HasSuffix(path, ".sh") || strings.Contains(path, "/usr/local/sbin/") {
			mode = 0o755
		}
		if err := os.WriteFile(dest, []byte(body), mode); err != nil {
			return Result{}, err
		}
		wrote = append(wrote, rel)
	}
	if err := os.WriteFile(filepath.Join(stage, "canonical.txt"), []byte(canon), 0o644); err != nil {
		return Result{}, err
	}
	if err := writeManifest(stage, to); err != nil {
		return Result{}, err
	}
	sort.Strings(wrote)
	res.Wrote = wrote
	t := &txn{a: a, j: j, toFiles: local, rt: rt, rep: a.newReport(j)}
	t.rep.Warnings = append(t.rep.Warnings, notes...)
	var prevSysctl string
	if a.Install {
		prevSysctl = a.readHostSysctl()
	}
	if err := t.execute("安装"); err != nil {
		return Result{}, err
	}
	if a.Install {
		t.attachSysctl(prevSysctl)
		res.Host = t.rep
	}
	return res, nil
}

// Rollback restores the previous snapshot. A second rollback swaps again.
func (a Applier) Rollback() error {
	_, err := a.RollbackReport()
	return err
}

// RollbackReport is Rollback with the host transaction report. With Install
// it is a runtime rollback: the host is converged from the installed
// manifest to the previous snapshot's (removing files, interfaces, units and
// tables only the newer one owns) and activated from that manifest, all in
// one transaction with the snapshot swap.
func (a Applier) RollbackReport() (*HostReport, error) {
	unlock, err := a.begin()
	if err != nil {
		return nil, err
	}
	defer unlock()
	if inst, err := a.Installed(); err != nil {
		return nil, err
	} else if a.Install && inst.Withdrawn() {
		return nil, ErrWithdrawnState
	}
	root := a.data()
	previous := filepath.Join(root, "previous")
	if _, err := os.Stat(previous); err != nil {
		return nil, ErrNoPrevious
	}
	from, err := a.Installed()
	if err != nil {
		return nil, err
	}
	if !a.Install && !from.Empty() && !a.SnapshotOnly {
		return nil, ErrRuntimeRollbackRequired
	}
	files, err := readNodeFiles(previous, a.localID())
	if err != nil {
		return nil, err
	}
	var rt Runtime
	if a.Install {
		if _, err := a.prepareHost(files); err != nil {
			return nil, err
		}
		if rt, err = a.runtime(); err != nil {
			return nil, err
		}
		if err := a.probe(rt); err != nil {
			return nil, err
		}
		if _, err := a.adoptLegacy(rt, files); err != nil {
			return nil, err
		}
		if from, err = a.Installed(); err != nil {
			return nil, err
		}
	}
	before := a.snapshots()
	canon, _ := os.ReadFile(filepath.Join(previous, "canonical.txt"))
	to, err := DeriveManifest(a.localID(), files, before.Previous, string(canon))
	if err != nil {
		return nil, err
	}
	j := &journal{ID: newTxnID(), Kind: "snapshot", Install: a.Install, Phase: phasePrepared,
		From: from, To: to, Before: before, After: snapPair{Applied: before.Previous, Previous: before.Applied},
		Started: time.Now().UTC().Format(time.RFC3339)}
	if a.Install {
		j.Kind = "rollback"
	}
	t := &txn{a: a, j: j, toFiles: files, rt: rt, rep: a.newReport(j)}
	var prevSysctl string
	if a.Install {
		prevSysctl = a.readHostSysctl()
	}
	if err := t.execute("回滚"); err != nil {
		return nil, err
	}
	if !a.Install {
		return nil, nil
	}
	t.attachSysctl(prevSysctl)
	return t.rep, nil
}

// Recover finishes or undoes an unfinished transaction found in the journal
// (after a crash, a restart mid-transaction, or a failed compensation). A
// transaction that reached "commit" is completed; anything earlier is
// compensated back to the state before it. Without a journal it is a no-op.
// Compensating a host transaction needs PrivateKey and Host like an install.
func (a Applier) Recover() (*HostReport, error) {
	if err := os.MkdirAll(a.hostDir(), 0o750); err != nil {
		return nil, err
	}
	unlock, err := lockFile(filepath.Join(a.hostDir(), "txn.lock"))
	if err != nil {
		return nil, err
	}
	defer unlock()
	j, err := a.loadJournal()
	if err != nil || j == nil {
		return nil, err
	}
	t := &txn{a: a, j: j, rep: a.newReport(j)}
	if j.Phase == phaseCommit {
		if err := t.commit(); err != nil {
			return t.rep, err
		}
		t.rep.Committed = true
		return t.rep, nil
	}
	if j.Install && j.Phase != phasePrepared {
		if t.rt, err = a.runtime(); err != nil {
			return t.rep, err
		}
		if err := a.probe(t.rt); err != nil {
			return t.rep, err
		}
	}
	if j.Phase == phasePrepared {
		// Nothing on the host was touched yet; only the snapshots may move.
		j.Install = false
	}
	cause := errors.New("恢复中断的事务 " + j.ID)
	if j.Error != "" {
		cause = errors.New(j.Error)
	}
	err = t.abort("恢复", cause)
	var te *TxnError
	if errors.As(err, &te) && te.Compensated {
		return t.rep, nil
	}
	return t.rep, err
}

type hostFile struct {
	rel  string
	body []byte
	mode os.FileMode
}

// prepareHost checks paths and injects the private key in memory. Nothing is
// written; a missing or malformed key is reported here.
func (a Applier) prepareHost(files map[string]string) ([]hostFile, error) {
	rels := make([]string, 0, len(files))
	for rel := range files {
		rels = append(rels, rel)
	}
	sort.Strings(rels)
	out := make([]hostFile, 0, len(rels))
	for _, rel := range rels {
		if strings.Contains(rel, "..") || strings.HasPrefix(rel, "/") || !allowed(rel) {
			return nil, fmt.Errorf("拒绝安装路径 %s", rel)
		}
		body, err := InjectPrivateKey(rel, files[rel], a.PrivateKey)
		if err != nil {
			return nil, err
		}
		if body, err = InjectSecrets(rel, body, a.Secrets); err != nil {
			return nil, err
		}
		out = append(out, hostFile{rel: rel, body: []byte(body), mode: hostMode(rel)})
	}
	return out, nil
}

// nodeFiles returns one node's files from a bundle, keyed by host path
// without a leading slash.
func nodeFiles(bundle map[string]string, nodeID string) map[string]string {
	prefix := "nodes/" + nodeID + "/"
	out := map[string]string{}
	for p, body := range bundle {
		if strings.HasPrefix(p, prefix) {
			out[strings.TrimPrefix(p, prefix)] = body
		}
	}
	return out
}

func readNodeFiles(snapshot, nodeID string) (map[string]string, error) {
	base := filepath.Join(snapshot, "nodes", nodeID)
	out := map[string]string{}
	if _, err := os.Stat(base); os.IsNotExist(err) {
		return out, nil
	}
	err := filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(base, path)
		if err != nil {
			return err
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out[filepath.ToSlash(rel)] = string(body)
		return nil
	})
	return out, err
}

func hostMode(rel string) os.FileMode {
	switch {
	case isWireGuardConf(rel), compile.WSSSecretFile(rel):
		return 0o600
	case strings.HasSuffix(rel, ".sh") || strings.HasPrefix(rel, "usr/local/sbin/"):
		return 0o755
	default:
		return 0o644
	}
}

// writeHostFile replaces dest through a temp file in the same directory, so
// the final mode applies even when dest already existed with a wider one and
// a reader never sees a half-written file.
func writeHostFile(dest string, body []byte, mode os.FileMode) error {
	dirMode := os.FileMode(0o755)
	if mode == 0o600 {
		dirMode = 0o700
	}
	dir := filepath.Dir(dest)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".meridian-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, dest)
}

// HostPathAllowed reports whether an absolute path is one Meridian may write.
func HostPathAllowed(p string) bool {
	rel := strings.TrimPrefix(filepath.ToSlash(p), "/")
	if rel == "" || strings.Contains(rel, "..") || strings.HasPrefix(rel, "/") {
		return false
	}
	return allowed(rel)
}

func safeBundlePath(path string) (string, error) {
	if strings.Contains(path, "..") || filepath.IsAbs(path) {
		return "", fmt.Errorf("非法路径 %s", path)
	}
	clean := filepath.ToSlash(filepath.Clean(path))
	if clean == "APPLY_ORDER.txt" || clean == "README.txt" || clean == "canonical.txt" {
		return clean, nil
	}
	if strings.HasPrefix(clean, "nodes/") {
		rest := strings.TrimPrefix(clean, "nodes/")
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) == 2 && allowed(parts[1]) {
			return clean, nil
		}
	}
	return "", fmt.Errorf("拒绝写入路径 %s", path)
}

func allowed(rel string) bool {
	for _, p := range allowedPrefixes {
		if strings.HasPrefix(rel, p) {
			return true
		}
	}
	return false
}

// Unified is a small line diff. It is meant for review in the panel, not as a patch tool.
func Unified(prev, next string) string {
	if prev == next {
		return "（没有变化）\n"
	}
	a := strings.Split(prev, "\n")
	b := strings.Split(next, "\n")
	// File-boundary aware: split both texts on the ===== headers and diff per file.
	af := splitFiles(prev)
	bf := splitFiles(next)
	keys := map[string]bool{}
	for k := range af {
		keys[k] = true
	}
	for k := range bf {
		keys[k] = true
	}
	var names []string
	for k := range keys {
		names = append(names, k)
	}
	sort.Strings(names)
	var sb strings.Builder
	if len(names) == 0 {
		return lineDiff("bundle", a, b)
	}
	for _, name := range names {
		if af[name] == bf[name] {
			continue
		}
		status := "changed"
		switch {
		case af[name] == "" && bf[name] != "":
			status = "added"
		case bf[name] == "" && af[name] != "":
			status = "removed"
		}
		fmt.Fprintf(&sb, "===== %s (%s) =====\n", name, status)
		sb.WriteString(lineDiff(name, strings.Split(af[name], "\n"), strings.Split(bf[name], "\n")))
	}
	if sb.Len() == 0 {
		return "（没有变化）\n"
	}
	return sb.String()
}

func splitFiles(canon string) map[string]string {
	out := map[string]string{}
	var name string
	var buf strings.Builder
	flush := func() {
		if name != "" {
			out[name] = buf.String()
		}
		buf.Reset()
	}
	for _, line := range strings.Split(canon, "\n") {
		if strings.HasPrefix(line, "===== ") && strings.HasSuffix(line, " =====") {
			flush()
			name = strings.TrimSuffix(strings.TrimPrefix(line, "===== "), " =====")
			continue
		}
		if name == "" {
			continue
		}
		buf.WriteString(line)
		buf.WriteByte('\n')
	}
	flush()
	return out
}

func lineDiff(name string, a, b []string) string {
	// Bound the work. Config files are small; if one is huge, show a clipped view.
	if len(a) > 4000 || len(b) > 4000 {
		return fmt.Sprintf("# %s is large (%d -> %d lines); review the rendered file\n", name, len(a), len(b))
	}
	lcs := lcsTable(a, b)
	var sb strings.Builder
	var walk func(i, j int)
	walk = func(i, j int) {
		if i > 0 && j > 0 && a[i-1] == b[j-1] {
			walk(i-1, j-1)
			fmt.Fprintf(&sb, " %s\n", a[i-1])
			return
		}
		if j > 0 && (i == 0 || lcs[i][j-1] >= lcs[i-1][j]) {
			walk(i, j-1)
			fmt.Fprintf(&sb, "+%s\n", b[j-1])
			return
		}
		if i > 0 && (j == 0 || lcs[i][j-1] < lcs[i-1][j]) {
			walk(i-1, j)
			fmt.Fprintf(&sb, "-%s\n", a[i-1])
			return
		}
	}
	walk(len(a), len(b))
	return sb.String()
}

func lcsTable(a, b []string) [][]int {
	n, m := len(a), len(b)
	dp := make([][]int, n+1)
	for i := range dp {
		dp[i] = make([]int, m+1)
	}
	for i := 1; i <= n; i++ {
		for j := 1; j <= m; j++ {
			if a[i-1] == b[j-1] {
				dp[i][j] = dp[i-1][j-1] + 1
			} else if dp[i-1][j] >= dp[i][j-1] {
				dp[i][j] = dp[i-1][j]
			} else {
				dp[i][j] = dp[i][j-1]
			}
		}
	}
	return dp
}
