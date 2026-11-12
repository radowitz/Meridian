// Package apply stores rendered bundles, diffs them, and can install the
// gateway's files without touching the rest of the host ruleset.
package apply

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/radowitz/meridian/internal/compile"
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
}

type Applier struct {
	DataDir string
	// Install copies the local gateway files into / when true.
	// Tests and the panel default to a data-dir render plus an explicit install.
	Install bool
	// LocalID is the node whose files are installed on this host (the gateway).
	LocalID string
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

// Diff compares the last applied canonical text with the candidate.
func (a Applier) Diff(next string) (string, error) {
	prev, err := os.ReadFile(filepath.Join(a.data(), "applied", "canonical.txt"))
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	return Unified(string(prev), next), nil
}

// Apply records the bundle. When Install is set, gateway files are copied
// into the host filesystem and the previous tree is kept for rollback.
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
	root := a.data()
	staging := filepath.Join(root, "staging")
	if err := os.RemoveAll(staging); err != nil {
		return Result{}, err
	}
	var wrote []string
	for path, body := range b.Files {
		rel, err := safeBundlePath(path)
		if err != nil {
			return Result{}, err
		}
		dest := filepath.Join(staging, rel)
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
	if err := os.WriteFile(filepath.Join(staging, "canonical.txt"), []byte(canon), 0o644); err != nil {
		return Result{}, err
	}
	applied := filepath.Join(root, "applied")
	previous := filepath.Join(root, "previous")
	_ = os.RemoveAll(previous)
	if _, err := os.Stat(applied); err == nil {
		if err := os.Rename(applied, previous); err != nil {
			return Result{}, err
		}
	}
	if err := os.Rename(staging, applied); err != nil {
		return Result{}, err
	}
	sort.Strings(wrote)
	res.Wrote = wrote
	if a.Install {
		if err := a.installLocal(applied); err != nil {
			// Roll the recorded snapshot back if the host copy fails.
			_ = a.Rollback()
			return Result{}, err
		}
	}
	return res, nil
}

// Rollback restores the previous snapshot. A second rollback swaps again.
func (a Applier) Rollback() error {
	root := a.data()
	applied := filepath.Join(root, "applied")
	previous := filepath.Join(root, "previous")
	if _, err := os.Stat(previous); err != nil {
		return fmt.Errorf("没有可回滚的上一份配置")
	}
	tmp := filepath.Join(root, "rollback-tmp")
	_ = os.RemoveAll(tmp)
	if _, err := os.Stat(applied); err == nil {
		if err := os.Rename(applied, tmp); err != nil {
			return err
		}
	}
	if err := os.Rename(previous, applied); err != nil {
		return err
	}
	if _, err := os.Stat(tmp); err == nil {
		if err := os.Rename(tmp, previous); err != nil {
			return err
		}
	}
	if a.Install {
		return a.installLocal(applied)
	}
	return nil
}

func (a Applier) installLocal(applied string) error {
	prefix := filepath.Join("nodes", a.localID())
	return filepath.Walk(filepath.Join(applied, prefix), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(filepath.Join(applied, prefix), path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if !allowed(rel) {
			return fmt.Errorf("拒绝安装路径 %s", rel)
		}
		dest := "/" + rel
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return err
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(dest, body, info.Mode())
	})
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
