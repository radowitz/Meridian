package apply

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// The managed sysctl files of the gateway and what an install reports
// about them.
//
// What is written: every install writes etc/sysctl.d/99-meridian.conf and
// etc/meridian/forwarding.conf from the compiled bundle, whole, whether or
// not they changed (converge writes every target file). Lines an older
// version or deploy/debian/install.sh left in 99-meridian.conf are
// therefore gone from the FILE after the first panel install.
//
// What is in effect: meridian-up.sh (run by meridian.service at activation)
// applies each line of 99-meridian.conf except the two boot-time forwarding
// lines, then forwarding.conf. A key the kernel does not have (an interface
// that does not exist) is skipped. Removing a line from the file does not
// change the running kernel: a key that only the previous file set keeps its
// value until reboot. Meridian does not know the value it had before and
// does not "reset" it.
//
// What is shown: SysctlReport, attached to the install's (and runtime
// rollback's) HostReport, lists every written key with the value read back
// from the kernel after activation, the keys removed from the file with
// their current kernel value, and a warning per problem.

const (
	SysctlFile     = "etc/sysctl.d/99-meridian.conf"
	ForwardingFile = "etc/meridian/forwarding.conf"
)

// Sysctl entry states.
const (
	SysctlInEffect   = "in_effect"   // the kernel has the value the file sets
	SysctlDiffers    = "differs"     // the kernel has another value
	SysctlMissing    = "missing"     // the kernel has no such key (interface absent?)
	SysctlBootOnly   = "boot_only"   // boot-time forwarding=0; runtime value comes from forwarding.conf
	SysctlStale      = "stale"       // removed from the file; the kernel keeps its value until reboot
	SysctlNotChecked = "not_checked" // the kernel was not read (test root, no /proc)
)

type SysctlEntry struct {
	File  string `json:"file"`
	Key   string `json:"key"`
	Want  string `json:"want,omitempty"`
	Got   string `json:"got,omitempty"`
	State string `json:"state"`
}

type SysctlReport struct {
	// Checked: the running kernel was read back after activation.
	Checked bool          `json:"checked"`
	Reason  string        `json:"reason,omitempty"`
	Written []SysctlEntry `json:"written"`
	// Removed: keys the previous 99-meridian.conf on the host set and the
	// new one does not.
	Removed []SysctlEntry `json:"removed,omitempty"`
	// Problems counts written entries that are not in effect (differs or
	// missing); the same entries are also HostReport warnings.
	Problems int `json:"problems"`
}

type sysctlLine struct{ key, val string }

// parseSysctlFile reads key=value lines (sysctl.d syntax: comments with
// '#' or ';', a leading '-' meaning "ignore errors", spaces around '=').
func parseSysctlFile(body string) []sysctlLine {
	var out []sysctlLine
	for _, ln := range strings.Split(body, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || ln[0] == '#' || ln[0] == ';' {
			continue
		}
		ln = strings.TrimPrefix(ln, "-")
		k, v, ok := strings.Cut(ln, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if k == "" {
			continue
		}
		out = append(out, sysctlLine{key: strings.ReplaceAll(k, "/", "."), val: v})
	}
	return out
}

func isBootForwarding(key string) bool {
	return key == "net.ipv4.ip_forward" || key == "net.ipv6.conf.all.forwarding"
}

// procSysctlPath maps a dotted key to its /proc/sys path. For
// net.ipv{4,6}.conf.<if>.<param> and net.ipv{4,6}.neigh.<if>.<param> the
// interface part keeps its dots (eth0.100 is one name).
func procSysctlPath(key string) string {
	parts := strings.Split(key, ".")
	if len(parts) >= 5 && parts[0] == "net" && (parts[1] == "ipv4" || parts[1] == "ipv6") && (parts[2] == "conf" || parts[2] == "neigh") {
		iface := strings.Join(parts[3:len(parts)-1], ".")
		return filepath.Join("/proc/sys", parts[0], parts[1], parts[2], iface, parts[len(parts)-1])
	}
	return filepath.Join(append([]string{"/proc/sys"}, parts...)...)
}

// ProcSysctl reads one key of the running kernel from /proc/sys. The panel
// container runs with host networking, so net.* keys are the host's.
func ProcSysctl(key string) (string, error) {
	b, err := os.ReadFile(procSysctlPath(key))
	if err != nil {
		return "", err
	}
	return strings.Join(strings.Fields(string(b)), " "), nil
}

func (a Applier) sysctlReader() (func(string) (string, error), string) {
	if a.ReadSysctl != nil {
		return a.ReadSysctl, ""
	}
	if filepath.Clean(a.hostRoot()) != "/" {
		return nil, "安装写到测试目录，没有读取运行中的内核"
	}
	return ProcSysctl, ""
}

// readHostSysctl is the 99-meridian.conf on the host before an install
// writes it ("" when absent or unreadable).
func (a Applier) readHostSysctl() string {
	b, err := os.ReadFile(filepath.Join(a.hostRoot(), filepath.FromSlash(SysctlFile)))
	if err != nil {
		return ""
	}
	return string(b)
}

// sysctlReport compares the written managed sysctl files with the running
// kernel (after activation) and with the file that was on the host before.
func (a Applier) sysctlReport(previous string, files map[string]string) *SysctlReport {
	sys, ok := files[SysctlFile]
	if !ok {
		return nil
	}
	read, reason := a.sysctlReader()
	rep := &SysctlReport{Checked: read != nil, Reason: reason, Written: []SysctlEntry{}}
	check := func(file string, l sysctlLine, boot bool) SysctlEntry {
		e := SysctlEntry{File: "/" + file, Key: l.key, Want: l.val, State: SysctlNotChecked}
		if read == nil {
			if boot {
				e.State = SysctlBootOnly
			}
			return e
		}
		got, err := read(l.key)
		switch {
		case err != nil:
			e.State = SysctlMissing
		case boot:
			e.Got, e.State = got, SysctlBootOnly
		case got == l.val || strings.Join(strings.Fields(got), " ") == strings.Join(strings.Fields(l.val), " "):
			e.Got, e.State = got, SysctlInEffect
		default:
			e.Got, e.State = got, SysctlDiffers
		}
		return e
	}
	written := map[string]bool{}
	for _, l := range parseSysctlFile(sys) {
		written[l.key] = true
		rep.Written = append(rep.Written, check(SysctlFile, l, isBootForwarding(l.key)))
	}
	for _, l := range parseSysctlFile(files[ForwardingFile]) {
		rep.Written = append(rep.Written, check(ForwardingFile, l, false))
	}
	for _, e := range rep.Written {
		if e.State == SysctlDiffers || e.State == SysctlMissing {
			rep.Problems++
		}
	}
	seen := map[string]bool{}
	for _, l := range parseSysctlFile(previous) {
		if written[l.key] || seen[l.key] {
			continue
		}
		seen[l.key] = true
		e := SysctlEntry{File: "/" + SysctlFile, Key: l.key, Want: l.val, State: SysctlStale}
		if read != nil {
			if got, err := read(l.key); err == nil {
				e.Got = got
			}
		}
		rep.Removed = append(rep.Removed, e)
	}
	sort.SliceStable(rep.Removed, func(i, j int) bool { return rep.Removed[i].Key < rep.Removed[j].Key })
	return rep
}

// Warnings are the report's problems as HostReport warning lines.
func (r *SysctlReport) Warnings() []string {
	if r == nil {
		return nil
	}
	var out []string
	for _, e := range r.Written {
		switch e.State {
		case SysctlDiffers:
			out = append(out, "内核参数 "+e.Key+" 现在是 "+e.Got+"，"+e.File+" 写的是 "+e.Want+"：meridian-up.sh 设置后又被改掉，或设置失败（看 journalctl -u meridian.service 里的 skip sysctl）")
		case SysctlMissing:
			out = append(out, "内核没有参数 "+e.Key+"（"+e.File+"）：多半是接口名不存在，meridian-up.sh 跳过了这一行；检查拓扑的局域网接口")
		}
	}
	if n := len(r.Removed); n > 0 {
		keys := make([]string, 0, n)
		for _, e := range r.Removed {
			keys = append(keys, e.Key)
		}
		out = append(out, "旧的 99-meridian.conf 里有 "+strings.Join(keys, "、")+"，新文件已不再设置；文件已更新，但运行中的内核保留原值直到重启（Meridian 不知道原来的默认值，不去改它）")
	}
	return out
}
