package hostexec

// The gateway install pre-check (POST /v1/preflight).
//
// It is the host-agent counterpart of the remote preflight script
// (internal/preflight): read-only, and it answers in the same report
// format, so the panel evaluates both with the same code. The only
// parameter is the list of host paths the gateway bundle would write;
// each must pass preflight.ValidatePaths (absolute, clean, a fixed set of
// directories, no shell or glob characters). Programs come from the fixed
// table (ip, nft, ss, iptables, ip6tables, systemctl, wg, and docker for
// one "inspect" of the fixed SmartDNS container) with fixed
// argument lists; files are read directly and never reported, only their
// type, size, whether the first lines mention Meridian, and a SHA-256.
// Like health it takes no action lock and is not cached by request id.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/radowitz/meridian/internal/preflight"
)

// PreflightRequest names the paths to inspect.
type PreflightRequest struct {
	Paths []string `json:"paths"`
}

// PreflightResult carries the report text.
type PreflightResult struct {
	Report string `json:"report"`
	Error  string `json:"error,omitempty"`
}

// ValidatePreflight checks a request completely before anything runs.
func ValidatePreflight(req PreflightRequest) error {
	return preflight.ValidatePaths(req.Paths)
}

// preflightUnits are the services whose state the report includes.
var preflightUnits = []string{
	"docker.service", "containerd.service", "nftables.service", "netfilter-persistent.service", "ufw.service",
	"firewalld.service", "smartdns.service", "systemd-resolved.service", "warp-svc.service",
}

// commandDirs are where command presence is looked up (PATH is never used).
var commandDirs = []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"}

// Preflight produces the report. Files are read relative to root ("" = /);
// tests point it at a temp dir.
func (a *Agent) Preflight(ctx context.Context, req PreflightRequest) PreflightResult {
	a.init()
	if err := ValidatePreflight(req); err != nil {
		return PreflightResult{Error: err.Error()}
	}
	timeout := a.StepTimeout
	if timeout > 15*time.Second {
		timeout = 15 * time.Second
	}
	x := &run{a: a, ctx: ctx}
	root := a.PreflightRoot
	var b bytes.Buffer
	complete := true
	w := func(key string, fields ...string) { b.WriteString(preflight.Line(key, fields...)) }
	// cmd runs one fixed program and returns its output, or "" on error.
	// An answer at the runner's output cap may be cut: the report is then
	// marked incomplete (no end line).
	cmd := func(prog string, args ...string) string {
		out, err := x.cmd(timeout, prog, args...)
		if len(out) >= 16<<10 {
			complete = false
			w("note", prog+" "+strings.Join(args, " ")+" 的输出达到上限，可能不完整")
		}
		if err != nil && out == "" {
			return ""
		}
		return out
	}
	lines := func(key, text string, max int) {
		n := 0
		for _, l := range strings.Split(text, "\n") {
			if strings.TrimSpace(l) == "" {
				continue
			}
			if n >= max {
				complete = false
				w("note", key+" 行数超过上限")
				return
			}
			w(key, l)
			n++
		}
	}
	readFile := func(p string, max int64) string {
		f, err := os.Open(filepath.Join(root, p))
		if err != nil {
			return ""
		}
		defer f.Close()
		buf, _ := io.ReadAll(io.LimitReader(f, max))
		return string(buf)
	}

	b.WriteString(preflight.Header + "\n")
	w("uid", fmt.Sprint(os.Geteuid()))
	w("arch", map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[runtime.GOARCH]+orGOARCH(runtime.GOARCH))
	w("kernel", strings.TrimSpace(readFile("/proc/sys/kernel/osrelease", 128)))
	osr := readFile("/etc/os-release", 8<<10)
	for _, kv := range [][2]string{{"ID", "os-id"}, {"VERSION_ID", "os-version"}, {"VERSION_CODENAME", "os-codename"}, {"PRETTY_NAME", "os-pretty"}} {
		if v, ok := osRelease(osr, kv[0]); ok {
			w(kv[1], v)
		}
	}
	if st, err := os.Stat(filepath.Join(root, "/run/systemd/system")); err == nil && st.IsDir() {
		w("systemd", "yes")
	} else {
		w("systemd", "no")
	}
	mem := readFile("/proc/meminfo", 16<<10)
	for _, kv := range [][2]string{{"MemTotal:", "mem-total-kb"}, {"MemAvailable:", "mem-avail-kb"}} {
		for _, l := range strings.Split(mem, "\n") {
			if f := strings.Fields(l); len(f) >= 2 && f[0] == kv[0] {
				w(kv[1], f[1])
			}
		}
	}
	if v := diskAvailKB(filepath.Join(root, "/")); v >= 0 {
		w("disk-avail-kb", fmt.Sprint(v))
	}
	for _, c := range []string{"wg", "wg-quick", "nft", "ip", "ss", "iptables", "ip6tables", "apt-get", "systemctl", "smartdns", "wstunnel", "docker", "sha256sum"} {
		w("cmd", c, yesNo(hasCommand(root, c)))
	}
	if v := cmd("iptables", "-V"); v != "" {
		w("iptables-version", firstLine(v))
	}
	for _, ch := range []string{"INPUT", "FORWARD"} {
		if v := cmd("iptables", "-w", "5", "-S", ch); v != "" {
			w("ipt", "ipv4", firstLine(v))
		}
		if v := cmd("ip6tables", "-w", "5", "-S", ch); v != "" {
			w("ipt", "ipv6", firstLine(v))
		}
	}
	for _, k := range []string{"net/ipv4/ip_forward", "net/ipv6/conf/all/forwarding", "net/ipv4/conf/all/rp_filter"} {
		if v := readFile("/proc/sys/"+k, 32); v != "" {
			w("sysctl", strings.ReplaceAll(k, "/", "."), strings.TrimSpace(v))
		}
	}
	for _, l := range strings.Split(cmd("ip", "-o", "link", "show"), "\n") {
		if name := linkName(l); name != "" {
			w("link", name)
		}
	}
	for _, l := range strings.Split(cmd("ip", "-o", "link", "show", "type", "wireguard"), "\n") {
		if name := linkName(l); name != "" {
			w("wglink", name)
		}
	}
	for _, l := range strings.Split(cmd("ip", "-o", "addr", "show"), "\n") {
		if f := strings.Fields(l); len(f) >= 4 {
			w("addr", strings.SplitN(f[1], "@", 2)[0], f[3])
		}
	}
	lines("route4", cmd("ip", "-4", "route", "show", "table", "main"), 600)
	lines("route6", cmd("ip", "-6", "route", "show", "table", "main"), 600)
	lines("rule4", cmd("ip", "-4", "rule", "show"), 300)
	lines("rule6", cmd("ip", "-6", "rule", "show"), 300)
	for fam, key := range map[string]string{"-4": "rtable4", "-6": "rtable6"} {
		seen := map[string]bool{}
		for _, l := range strings.Split(cmd("ip", fam, "route", "show", "table", "all"), "\n") {
			f := strings.Fields(l)
			for i := 0; i+1 < len(f); i++ {
				if f[i] == "table" {
					kind := "route"
					if f[0] == "default" {
						kind = "default"
					}
					if !seen[f[i+1]+kind] {
						seen[f[i+1]+kind] = true
						w(key, f[i+1], kind)
					}
				}
			}
		}
	}
	lines("wgport", cmd("wg", "show", "all", "listen-port"), 200)
	for _, p := range []string{"/usr/share/iproute2/rt_tables", "/etc/iproute2/rt_tables"} {
		rtNames(readFile(p, 64<<10), w)
	}
	if ents, err := os.ReadDir(filepath.Join(root, "/etc/iproute2/rt_tables.d")); err == nil {
		for _, e := range ents {
			if strings.HasSuffix(e.Name(), ".conf") {
				rtNames(readFile("/etc/iproute2/rt_tables.d/"+e.Name(), 64<<10), w)
			}
		}
	}
	lines("ss", cmd("ss", "-Hlntup"), 600)
	// Under the agent's least-privilege unit (no CAP_SYS_PTRACE) "ss -p"
	// cannot see which process holds a socket. The socket's cgroup comes
	// from sock_diag and needs no access to the process: it names the
	// unit or container that opened it.
	lines("ssc", cmd("ss", "-Hlntu", "--cgroup"), 600)
	// The compose-managed SmartDNS container (fixed name): its id, so a
	// listener in its cgroup can be attributed to it.
	if hasCommand(root, "docker") {
		out := strings.Fields(firstLine(cmd("docker", "inspect", "--format", "{{.Id}} {{.State.Running}}", SmartDNSContainer)))
		if len(out) == 2 {
			w("container", SmartDNSContainer, out[0], out[1])
		}
	}
	for _, l := range strings.Split(cmd("nft", "list", "chains"), "\n") {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "table ") || strings.HasPrefix(t, "chain ") || strings.HasPrefix(t, "type ") {
			w("nft", t)
		}
	}
	unit := func(u string) {
		act := strings.TrimSpace(firstLine(cmd("systemctl", "is-active", u)))
		en := strings.TrimSpace(firstLine(cmd("systemctl", "is-enabled", u)))
		pid := strings.TrimSpace(firstLine(cmd("systemctl", "show", "-p", "MainPID", "--value", u)))
		w("unit", u, orMinus(act), orMinus(en), orZero(pid))
	}
	for _, u := range preflightUnits {
		unit(u)
	}
	if conf := readFile("/etc/nftables.conf", 256<<10); conf != "" {
		state := "noflush"
		for _, l := range strings.Split(conf, "\n") {
			if f := strings.Fields(l); len(f) >= 2 && f[0] == "flush" && f[1] == "ruleset" {
				state = "flush"
			}
		}
		w("nftables-conf", state)
	} else {
		w("nftables-conf", "absent")
	}
	paths := append([]string(nil), req.Paths...)
	sort.Strings(paths)
	for _, p := range paths {
		limit := int64(4 << 20)
		if preflight.IsArtifactPath(p) {
			// Panel-delivered binaries are hashed up to the delivery bound.
			limit = 64 << 20
		}
		w("path", append([]string{p}, inspectPath(filepath.Join(root, p), limit)...)...)
		if strings.HasPrefix(p, "/etc/systemd/system/") && ValidUnit(filepath.Base(p)) {
			unit(filepath.Base(p))
		}
	}
	if complete {
		b.WriteString(preflight.EndMarker + "\n")
	}
	out := b.String()
	if len(out) > preflight.MaxReport {
		out = out[:preflight.MaxReport+1]
	}
	return PreflightResult{Report: out}
}

func orGOARCH(a string) string {
	if a == "amd64" || a == "arm64" {
		return ""
	}
	return a
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func orMinus(s string) string {
	if s == "" {
		return "-"
	}
	return strings.Fields(s)[0]
}

func orZero(s string) string {
	if s == "" {
		return "0"
	}
	return strings.Fields(s)[0]
}

func hasCommand(root, name string) bool {
	for _, d := range commandDirs {
		if st, err := os.Stat(filepath.Join(root, d, name)); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return true
		}
	}
	return false
}

func linkName(l string) string {
	f := strings.SplitN(l, ": ", 3)
	if len(f) < 2 {
		return ""
	}
	return strings.SplitN(strings.TrimSpace(f[1]), "@", 2)[0]
}

func osRelease(text, key string) (string, bool) {
	for _, l := range strings.Split(text, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), key+"="); ok {
			return strings.Trim(v, `"'`), true
		}
	}
	return "", false
}

func rtNames(text string, w func(string, ...string)) {
	for _, l := range strings.Split(text, "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 && !strings.HasPrefix(f[0], "#") {
			if _, err := fmt.Sscanf(f[0], "%d", new(int)); err == nil {
				w("rtname", f[0], f[1])
			}
		}
	}
}

// inspectPath reports a path the way the remote script does: type, size,
// whether the first 12 lines mention Meridian, SHA-256 (files up to limit
// bytes: 4 MiB, 64 MiB for a panel-delivered binary).
func inspectPath(p string, limit int64) []string {
	st, err := os.Lstat(p)
	if err != nil {
		return []string{"absent"}
	}
	switch {
	case st.Mode()&os.ModeSymlink != 0:
		return []string{"link", "0", "no", "-"}
	case st.IsDir():
		return []string{"dir", "0", "no", "-"}
	case !st.Mode().IsRegular():
		return []string{"other", "0", "no", "-"}
	}
	f, err := os.Open(p)
	if err != nil {
		return []string{"file", fmt.Sprint(st.Size()), "no", "-"}
	}
	defer f.Close()
	marker := "no"
	sc := bufio.NewScanner(io.LimitReader(f, 8<<10))
	for i := 0; i < 12 && sc.Scan(); i++ {
		if strings.Contains(strings.ToLower(sc.Text()), "meridian") {
			marker = "yes"
			break
		}
	}
	sum := "-"
	if st.Size() <= limit {
		if _, err := f.Seek(0, io.SeekStart); err == nil {
			h := sha256.New()
			if _, err := io.Copy(h, io.LimitReader(f, limit)); err == nil {
				sum = hex.EncodeToString(h.Sum(nil))
			}
		}
	}
	return []string{"file", fmt.Sprint(st.Size()), marker, sum}
}

func (a *Agent) servePreflight(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(w, r) {
		return
	}
	var req PreflightRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, PreflightResult{Error: "请求格式不正确"})
		return
	}
	if err := ValidatePreflight(req); err != nil {
		writeJSON(w, http.StatusBadRequest, PreflightResult{Error: err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	writeJSON(w, http.StatusOK, a.Preflight(ctx, req))
}

// ErrPreflightUnsupported: the agent answered 404 (an older meridian-host
// without the preflight action).
var ErrPreflightUnsupported = errors.New("meridian-host 不支持安装前预检（版本过旧），请先升级宿主上的 meridian-host")

// Preflight asks the agent for the gateway report.
func (c *Client) Preflight(ctx context.Context, paths []string) (string, error) {
	req := PreflightRequest{Paths: paths}
	if err := ValidatePreflight(req); err != nil {
		return "", err
	}
	var res PreflightResult
	code, err := c.post(ctx, "/v1/preflight", req, 3*time.Minute, &res)
	if err != nil {
		if code == http.StatusNotFound {
			return "", ErrPreflightUnsupported
		}
		return "", err
	}
	switch {
	case code == http.StatusNotFound:
		return "", ErrPreflightUnsupported
	case code != http.StatusOK:
		return "", fmt.Errorf("host agent 拒绝预检（%d）：%s", code, res.Error)
	case res.Error != "":
		return "", errors.New(res.Error)
	}
	return res.Report, nil
}
